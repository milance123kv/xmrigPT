#ifndef XMRIG_NETWORK_H
#define XMRIG_NETWORK_H
#include "3rdparty/rapidjson/fwd.h"
#include "base/api/interfaces/IApiListener.h"
#include "base/kernel/interfaces/IBaseListener.h"
#include "base/kernel/interfaces/IStrategyListener.h"
#include "base/kernel/interfaces/ITimerListener.h"
#include "base/tools/Object.h"
#include "interfaces/IJobResultListener.h"
#include <vector>
namespace xmrig {
    class Controller;
    class IStrategy;
    class NetworkState;
    class Network : public IJobResultListener, public IStrategyListener, public IBaseListener, public ITimerListener, public IApiListener
    {
    public:
        XMRIG_DISABLE_COPY_MOVE_DEFAULT(Network)
            Network(Controller* controller);
        ~Network() override;
        inline IStrategy* strategy() const { return m_strategy; }
        void connect();
        void execCommand(char command);
    protected:
        inline void onTimer(const Timer*) override { tick(); }
        void onActive(IStrategy* strategy, IClient* client) override;
        void onConfigChanged(Config* config, Config* previousConfig) override;
        void onJob(IStrategy* strategy, IClient* client, const Job& job, const rapidjson::Value& params) override;
        void onJobResult(const JobResult& result) override;
        void onLogin(IStrategy* strategy, IClient* client, rapidjson::Document& doc, rapidjson::Value& params) override;
        void onPause(IStrategy* strategy) override;
        void onResultAccepted(IStrategy* strategy, IClient* client, const SubmitResult& result, const char* error) override;
        void onVerifyAlgorithm(IStrategy* strategy, const  IClient* client, const Algorithm& algorithm, bool* ok) override;
#   ifdef XMRIG_FEATURE_API
        void onRequest(IApiRequest& request) override;
#   endif
    private:
        constexpr static int kTickInterval = 1 * 1000;
        void setJob(IClient* client, const Job& job, bool donate);
        void tick();
#   ifdef XMRIG_FEATURE_API
        void getConnection(rapidjson::Value& reply, rapidjson::Document& doc, int version) const;
        void getResults(rapidjson::Value& reply, rapidjson::Document& doc, int version) const;
#   endif
        Controller* m_controller;
        IStrategy* m_donate = nullptr;
        IStrategy* m_strategy = nullptr;
        NetworkState* m_state = nullptr;
        Timer* m_timer = nullptr;
        bool m_isPaused; // Added member variable
        bool m_retryCount;
    };
} // namespace xmrig
#endif // XMRIG_NETWORK_H