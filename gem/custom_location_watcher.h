#ifndef CHROME_BROWSER_CUSTOM_LOCATION_WATCHER_H_
#define CHROME_BROWSER_CUSTOM_LOCATION_WATCHER_H_

#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/win/reg_key.h"

namespace win_util {

class CustomLocationWatcher {
 public:
  CustomLocationWatcher();
  ~CustomLocationWatcher();

  // 감시 시작 (UI 스레드 등 어디서나 호출 가능)
  void Initialize();

 private:
  // 백그라운드 스레드에서 실행될 실제 감시 등록 함수
  void StartWatchingOnBackgroundSequence();
  
  // 레지스트리 변경 발생 시 백그라운드에서 호출되는 콜백
  void OnRegistryChanged();
  
  // 변경된 값을 기반으로 크롬 메인(UI) 스레드에 알림을 보내는 함수
  void NotifyLocationChangeToUIThread(const std::wstring& location);

  // 백그라운드 작업을 실행할 전용 시퀀스 런너
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  // 백그라운드 시퀀스에서만 접근하고 제어할 레지스트리 키 객체
  base::win::RegKey policy_key_;

  base::WeakPtrFactory<CustomLocationWatcher> weak_factory_{this};
};

}  // namespace win_util

#endif  // CHROME_BROWSER_CUSTOM_LOCATION_WATCHER_H_