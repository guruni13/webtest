#ifndef CHROME_BROWSER_CUSTOM_LOCATION_WATCHER_H_
#define CHROME_BROWSER_CUSTOM_LOCATION_WATCHER_H_

#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/win/reg_key.h"

namespace win_util {

// CustomLocationWatcher monitors a specific Windows registry key in real-time
// to determine whether the device is inside (on-premise) or outside (off-premise)
// the corporate network.
class CustomLocationWatcher {
 public:
  CustomLocationWatcher();
  ~CustomLocationWatcher();

  // Initializes the watcher and starts monitoring on a background thread.
  // Safe to call from the UI thread.
  void Initialize();

 private:
  // Sets up the registry watch on the background sequence.
  void StartWatchingOnBackgroundSequence();
  
  // Callback invoked on the background sequence when the registry key changes.
  void OnRegistryChanged();
  
  // Notifies the UI thread of the network location change.
  void NotifyLocationChangeToUIThread(const std::wstring& location);

  // Task runner dedicated to executing blocking registry operations.
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  // The registry key object used for watching. 
  // Must only be accessed on the background sequence.
  base::win::RegKey policy_key_;

  base::WeakPtrFactory<CustomLocationWatcher> weak_factory_{this};
};

}  // namespace win_util

#endif  // CHROME_BROWSER_CUSTOM_LOCATION_WATCHER_H_
