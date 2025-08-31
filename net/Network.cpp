#ifdef _MSC_VER
#pragma warning(disable:4244)
#endif
#include "net/Network.h"
#include "3rdparty/rapidjson/document.h"
#include "backend/common/Tags.h"
#include "base/io/log/Log.h"
#include "base/io/log/Tags.h"
#include "base/net/stratum/Client.h"
#include "base/net/stratum/NetworkState.h"
#include "base/net/stratum/SubmitResult.h"
#include "base/tools/Chrono.h"
#include "base/tools/Timer.h"
#include "core/config/Config.h"
#include "core/Controller.h"
#include "core/Miner.h"
#include "net/JobResult.h"
#include "net/JobResults.h"
#include "net/strategies/DonateStrategy.h"
#include <algorithm>
#include <cinttypes>
#include <ctime>
#include <iterator>
#include <memory>
#include <thread>
#include <chrono>
#ifdef XMRIG_FEATURE_API
#   include "base/api/Api.h"
#   include "base/api/interfaces/IApiRequest.h"
#endif
#ifdef XMRIG_FEATURE_BENCHMARK
#   include "backend/common/benchmark/BenchState.h"
#endif
namespace xmrig {
    constexpr uint64_t kReconnectInterval = 4; // 4 seconds 
    constexpr uint64_t kMaxReconnectInterval = 7; // 
    Network::Network(Controller* controller) :
        m_controller(controller),
        m_isPaused(false),
        m_retryCount(0)
    {
        JobResults::setListener(this, controller->config()->cpu().isHwAES());
        controller->addListener(this);
#   ifdef XMRIG_FEATURE_API
        controller->api()->addListener(this);
#   endif
        m_state = new NetworkState(this);
        const Pools& pools = controller->config()->pools();
        m_strategy = pools.createStrategy(m_state);
        if (pools.donateLevel() > 0) {
            m_donate = new DonateStrategy(controller, this);
        }
        m_timer = new Timer(this, kTickInterval, kTickInterval);
    }
    Network::~Network()
    {
        JobResults::stop();
        delete m_timer;
        delete m_donate;
        delete m_strategy;
        delete m_state;
    }
    void Network::connect()
    {
        m_strategy->connect();
    }
    void Network::execCommand(char command)
    {
        switch (command) {
        case 's':
        case 'S':
            m_state->printResults();
            break;
        case 'c':
        case 'C':
            m_state->printConnection();
            break;
        case 'p':
        case 'P':
            m_isPaused = true;
            LOG_INFO("%s " YELLOW_BOLD("mining paused"), Tags::network());
            break;
        case 'r':
        case 'R':
            m_isPaused = false;
            m_retryCount = 0; // Reset retry count on manual resume
            LOG_INFO("%s " GREEN_BOLD("mining resumed"), Tags::network());
            m_strategy->resume();
            break;
        default:
            break;
        }
    }
    void Network::onActive(IStrategy* strategy, IClient* client)
    {
        m_retryCount = 0; // Reset retry count on successful connection
        if (m_donate && m_donate == strategy) {
            LOG_NOTICE("%s " WHITE_BOLD("dev donate started"), Tags::network());
            return;
        }
        const auto& pool = client->pool();
#   ifdef XMRIG_FEATURE_BENCHMARK
        if (pool.mode() == Pool::MODE_BENCHMARK) {
            return;
        }
#   endif
        char zmq_buf[32] = {};
        if (client->pool().zmq_port() >= 0) {
            snprintf(zmq_buf, sizeof(zmq_buf), " (ZMQ:%d)", client->pool().zmq_port());
        }
        const char* tlsVersion = client->tlsVersion();
        LOG_INFO("%s " WHITE_BOLD("use %s ") CYAN_BOLD("%s:%d%s ") GREEN_BOLD("%s") " " BLACK_BOLD("%s"),
            Tags::network(), client->mode(), pool.host().data(), pool.port(), zmq_buf, tlsVersion ? tlsVersion : "", client->ip().data());
        const char* fingerprint = client->tlsFingerprint();
        if (fingerprint != nullptr) {
            LOG_INFO("%s " BLACK_BOLD("fingerprint (SHA-256): \"%s\""), Tags::network(), fingerprint);
        }
    }
    void Network::onConfigChanged(Config* config, Config* previousConfig)
    {
        if (config->pools() == previousConfig->pools() || !config->pools().active()) {
            return;
        }
        m_strategy->stop();
        config->pools().print();
        delete m_strategy;
        m_strategy = config->pools().createStrategy(m_state);
        connect();
    }
    void Network::onJob(IStrategy* strategy, IClient* client, const Job& job, const rapidjson::Value&)
    {
        if (m_isPaused) {
            return;
        }
        if (m_donate && m_donate->isActive() && m_donate != strategy) {
            return;
        }
        setJob(client, job, m_donate == strategy);
    }
    void Network::onJobResult(const JobResult& result)
    {
        if (result.index == 1 && m_donate) {
            m_donate->submit(result);
            return;
        }
        m_strategy->submit(result);
    }
    void Network::onLogin(IStrategy*, IClient* client, rapidjson::Document& doc, rapidjson::Value& params)
    {
        using namespace rapidjson;
        auto& allocator = doc.GetAllocator();
        Algorithms algorithms = m_controller->miner()->algorithms();
        const Algorithm algorithm = client->pool().algorithm();
        if (algorithm.isValid()) {
            const size_t index = static_cast<size_t>(std::distance(algorithms.begin(), std::find(algorithms.begin(), algorithms.end(), algorithm)));
            if (index > 0 && index < algorithms.size()) {
                std::swap(algorithms[0], algorithms[index]);
            }
        }
        Value algo(kArrayType);
        for (const auto& a : algorithms) {
            algo.PushBack(StringRef(a.name()), allocator);
        }
        params.AddMember("algo", algo, allocator);
    }
    void Network::onPause(IStrategy* strategy)
    {
        if (m_donate && m_donate == strategy) {
            LOG_NOTICE("%s " WHITE_BOLD("dev donate finished"), Tags::network());
            m_strategy->resume();
            return;
        }
        if (!m_strategy->isActive()) {
            m_retryCount++;
            uint64_t reconnectInterval = std::min<uint64_t>(kReconnectInterval * (1ULL << std::min<uint64_t>(m_retryCount, 5ULL)), kMaxReconnectInterval);
            LOG_ERR("%s " RED("no active pools, attempting to reconnect in %" PRIu64 " seconds (attempt %u)"), Tags::network(), reconnectInterval, m_retryCount);
            m_strategy->connect();
            std::this_thread::sleep_for(std::chrono::seconds(reconnectInterval));
            if (!m_strategy->isActive()) {
                // Trigger another connect attempt immediately to keep trying
                m_strategy->connect();
            }
        }
    }
    void Network::onResultAccepted(IStrategy*, IClient*, const SubmitResult& result, const char* error)
    {
        uint64_t diff = result.diff;
        const char* scale = NetworkState::scaleDiff(diff);
        if (error) {
            LOG_INFO("%s " RED_BOLD("rejected") " (%" PRId64 "/%" PRId64 ") diff " WHITE_BOLD("%" PRIu64 "%s") " " RED("\"%s\"") " " BLACK_BOLD("(%" PRIu64 " ms)"),
                backend_tag(result.backend), m_state->accepted(), m_state->rejected(), diff, scale, error, result.elapsed);
        }
        else {
            LOG_INFO("%s " GREEN_BOLD("accepted") " (%" PRId64 "/%" PRId64 ") diff " WHITE_BOLD("%" PRIu64 "%s") " " BLACK_BOLD("(%" PRIu64 " ms)"),
                backend_tag(result.backend), m_state->accepted(), m_state->rejected(), diff, scale, result.elapsed);
        }
    }
    void Network::onVerifyAlgorithm(IStrategy*, const IClient*, const Algorithm& algorithm, bool* ok)
    {
        if (!m_controller->miner()->isEnabled(algorithm)) {
            *ok = false;
            return;
        }
    }
#ifdef XMRIG_FEATURE_API
    void Network::onRequest(IApiRequest& request)
    {
        if (request.type() == IApiRequest::REQ_SUMMARY) {
            request.accept();
            getResults(request.reply(), request.doc(), request.version());
            getConnection(request.reply(), request.doc(), request.version());
        }
    }
#endif
    void Network::setJob(IClient* client, const Job& job, bool donate)
    {
        if (m_isPaused) {
            LOG_INFO("%s " YELLOW_BOLD("job assignment skipped (miner paused)"), Tags::network());
            return;
        }
#   ifdef XMRIG_FEATURE_BENCHMARK
        if (!BenchState::size())
#   endif
        {
            uint64_t diff = job.diff();
            const char* scale = NetworkState::scaleDiff(diff);
            char zmq_buf[32] = {};
            if (client->pool().zmq_port() >= 0) {
                snprintf(zmq_buf, sizeof(zmq_buf), " (ZMQ:%d)", client->pool().zmq_port());
            }
            char tx_buf[32] = {};
            const uint32_t num_transactions = job.getNumTransactions();
            if (num_transactions > 0) {
                snprintf(tx_buf, sizeof(tx_buf), " (%u tx)", num_transactions);
            }
            char height_buf[64] = {};
            if (job.height() > 0) {
                snprintf(height_buf, sizeof(height_buf), " height " WHITE_BOLD("%" PRIu64), job.height());
            }
            LOG_INFO("%s " MAGENTA_BOLD("new job") " from " WHITE_BOLD("%s:%d%s") " diff " WHITE_BOLD("%" PRIu64 "%s") " algo " WHITE_BOLD("%s") "%s%s",
                Tags::network(), client->pool().host().data(), client->pool().port(), zmq_buf, diff, scale, job.algorithm().name(), height_buf, tx_buf);
        }
        if (!donate && m_donate) {
            static_cast<DonateStrategy*>(m_donate)->update(client, job);
        }
        m_controller->miner()->setJob(job, donate);
    }
    void Network::tick()
    {
        const uint64_t now = Chrono::steadyMSecs();
        m_strategy->tick(now);
        if (m_donate) {
            m_donate->tick(now);
        }
#   ifdef XMRIG_FEATURE_API
        m_controller->api()->tick();
#   endif
    }
#ifdef XMRIG_FEATURE_API
    void Network::getConnection(rapidjson::Value& reply, rapidjson::Document& doc, int version) const
    {
        using namespace rapidjson;
        auto& allocator = doc.GetAllocator();
        reply.AddMember("algo", m_state->algorithm().toJSON(), allocator);
        reply.AddMember("connection", m_state->getConnection(doc, version), allocator);
    }
    void Network::getResults(rapidjson::Value& reply, rapidjson::Document& doc, int version) const
    {
        using namespace rapidjson;
        auto& allocator = doc.GetAllocator();
        reply.AddMember("results", m_state->getResults(doc, version), allocator);
    }
#endif
} // namespace xmrig