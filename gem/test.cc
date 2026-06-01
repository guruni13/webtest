void BrowserProcessImpl::PreMainMessageLoopRun() {
  // ... 기존 크롬 초기화 코드들 ...

#if BUILDFLAG(IS_WIN)
  // Windows 환경일 때만 감시자 객체를 생성하고 초기화합니다.
  custom_location_watcher_ = std::make_unique<win_util::CustomLocationWatcher>();
  custom_location_watcher_->Initialize();
#endif

  // ... 이하 생략 ...
}
