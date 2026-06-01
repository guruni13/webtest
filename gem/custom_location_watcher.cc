#include "chrome/browser/custom_location_watcher.h"

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/task/thread_pool.h"
#include "content/public/browser/browser_thread.h"

namespace win_util {

namespace {
// 감시할 레지스트리 경로 및 값 이름 정의
const wchar_t kPolicyRegistryPath[] = L"SOFTWARE\\Policies\\YourCompany\\NetworkSettings";
const wchar_t kLocationValueName[] = L"NetworkLocation";
}  // namespace

CustomLocationWatcher::CustomLocationWatcher() {
  // 파일 I/O 및 블로킹 작업이 가능한 전용 백그라운드 스레드 시퀀스를 생성합니다.
  background_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskPriority::USER_VISIBLE});
}

CustomLocationWatcher::~CustomLocationWatcher() {
  // 안전한 메모리 해제를 위해 레지스트리 키 닫기 처리를 백그라운드 시퀀스에 위임합니다.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&base::win::RegKey::Close,
                                base::Unretained(&policy_key_)));
}

void CustomLocationWatcher::Initialize() {
  // 감시 시작 로직을 백그라운드 시퀀스로 보냅니다.
  background_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&CustomLocationWatcher::StartWatchingOnBackgroundSequence,
                     weak_factory_.GetWeakPtr()));
}

void CustomLocationWatcher::StartWatchingOnBackgroundSequence() {
  // 백그라운드 스레드 위에서 레지스트리 키 열기
  if (!policy_key_.Valid()) {
    LONG result = policy_key_.Open(HKEY_LOCAL_MACHINE, kPolicyRegistryPath,
                                    KEY_NOTIFY | KEY_READ);
    if (result != ERROR_SUCCESS) {
      // 아직 외장 에이전트가 레지스트리 키를 생성하지 않았을 수 있으므로 주기적 재시도 등을 고려할 수 있습니다.
      VLOG(1) << "Failed to open registry policy key. Path might not exist yet.";
      return;
    }
  }

  // 실시간 감시 바인딩 (변경 시 OnRegistryChanged 호출)
  bool success = policy_key_.StartWatching(base::BindRepeating(
      &CustomLocationWatcher::OnRegistryChanged, weak_factory_.GetWeakPtr()));
      
  if (!success) {
    LOG(ERROR) << "Failed to start monitoring the registry path.";
  }
}

void CustomLocationWatcher::OnRegistryChanged() {
  // 값이 바뀌었으므로 새로 읽어옵니다.
  std::wstring location_status;
  LONG result = policy_key_.ReadValue(kLocationValueName, &location_status);
  
  if (result == ERROR_SUCCESS) {
    // 획득한 사내/사외 상태 값을 안전하게 UI 스레드로 전달합니다.
    content::BrowserThread::GetTaskRunnerForThread(content::BrowserThread::UI)
        ->PostTask(FROM_HERE,
                   base::BindOnce(&CustomLocationWatcher::NotifyLocationChangeToUIThread,
                                  weak_factory_.GetWeakPtr(), location_status));
  }

  // ⚠️ 중요: 다음 실시간 변경 감지를 위해 다시 체인을 연결합니다.
  StartWatchingOnBackgroundSequence();
}

void CustomLocationWatcher::NotifyLocationChangeToUIThread(const std::wstring& location) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  
  // 여기서 드디어 사내/사외 구분에 따른 크롬 제어 로직을 수행합니다!
  if (location == L"Work") {
    LOG(INFO) << "Laptop is INSIDE the office network. Activating corporate sync rules.";
    // 예: 이전에 구현을 논의했던 Sync Prefs나 컴포넌트 서비스들에 활성화 신호 전파
  } else {
    LOG(INFO) << "Laptop is OUTSIDE the office network. Restricting sync features.";
    // 예: 사외 보안 정책 적용
  }
}

}  // namespace win_util