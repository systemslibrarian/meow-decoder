package com.meowdecodermobile

import android.os.Bundle
import android.view.WindowManager
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

class MainActivity : ReactActivity() {

  override fun onCreate(savedInstanceState: Bundle?) {
    // Switch from SplashTheme (windowBackground logo) to AppTheme before React renders
    setTheme(R.style.AppTheme)
    super.onCreate(savedInstanceState)

    // SECURITY: FLAG_SECURE prevents:
    //   - Screenshots (system and third-party apps)
    //   - Screen recording via MediaProjection API
    //   - Content appearing in Android's recent-tasks switcher thumbnail
    //
    // This applies globally to all screens in the app, which is correct —
    // meow-decoder never wants any screen visible in recents or captured.
    // Apply unconditionally; there is no legitimate reason to disable it.
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
  }

  /** Returns the name of the main component registered from JavaScript. */
  override fun getMainComponentName(): String = "MeowCapture"

  /** Returns the instance of the [ReactActivityDelegate]. */
  override fun createReactActivityDelegate(): ReactActivityDelegate =
    DefaultReactActivityDelegate(this, mainComponentName, fabricEnabled)
}
