#include "chrome/browser/custom_location_watcher.h"

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/task/thread_pool.h"
#include "content/public/browser/browser_thread.h"

namespace win_util {

namespace {
// Define the registry path and value name to monitor.
constexpr wchar_t kPolicyRegistryPath[] = L"SOFTWARE\\Policies\\YourCompany\\NetworkSettings";
constexpr wchar_t kLocationValueName[] = L"NetworkLocation";
}  // namespace

CustomLocationWatcher::CustomLocationWatcher() {
  // Create a dedicated background sequence that allows blocking I/O operations.
  background_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::TaskPriority::USER_VISIBLE});
}

CustomLocationWatcher::~CustomLocationWatcher() {
  // Post a task to close the registry key on the background sequence 
  // to prevent memory leaks and ensure thread safety during destruction.
  background_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&base::win::RegKey::Close,
                                base::Unretained(&policy_key_)));
}

void CustomLocationWatcher::Initialize() {
  // Delegate the initialization and watching logic to the background sequence.
  background_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&CustomLocationWatcher::StartWatchingOnBackgroundSequence,
                     weak_factory_.GetWeakPtr()));
}

void CustomLocationWatcher::StartWatchingOnBackgroundSequence() {
  // Open the registry key on the background thread if it is not already open.
  if (!policy_key_.Valid()) {
    LONG result = policy_key_.Open(HKEY_LOCAL_MACHINE, kPolicyRegistryPath,
                                    KEY_NOTIFY | KEY_READ);
    if (result != ERROR_SUCCESS) {
      // The key might not exist yet if the corporate agent hasn't created it.
      VLOG(1) << "Failed to open registry policy key. Path might not exist yet.";
      return;
    }
  }

  // Register the asynchronous watch callback to intercept real-time changes.
  bool success = policy_key_.StartWatching(base::BindRepeating(
      &CustomLocationWatcher::OnRegistryChanged, weak_factory_.GetWeakPtr()));
      
  if (!success) {
    LOG(ERROR) << "Failed to start monitoring the registry path.";
  }
}

void CustomLocationWatcher::OnRegistryChanged() {
  // Read the updated value since the registry key has changed.
  std::wstring location_status;
  LONG result = policy_key_.ReadValue(kLocationValueName, &location_status);
  
  if (result == ERROR_SUCCESS) {
    // Safely forward the retrieved status to the UI thread.
    content::BrowserThread::GetTaskRunnerForThread(content::BrowserThread::UI)
        ->PostTask(FROM_HERE,
                   base::BindOnce(&CustomLocationWatcher::NotifyLocationChangeToUIThread,
                                  weak_factory_.GetWeakPtr(), location_status));
  }

  // CRITICAL: Re-arm the watch because StartWatching is a one-shot operation.
  StartWatchingOnBackgroundSequence();
}

void CustomLocationWatcher::NotifyLocationChangeToUIThread(const std::wstring& location) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  
  // Handle Chrome feature control logic based on corporate/public network location.
  if (location == L"Work") {
    LOG(INFO) << "Laptop is INSIDE the office network. Activating corporate sync rules.";
    // TODO: Propagate activation signals to SyncPrefs or other component services.
  } else {
    LOG(INFO) << "Laptop is OUTSIDE the office network. Restricting sync features.";
    // TODO: Apply enhanced security policies for off-premise environments.
  }
}

}  // namespace win_util
