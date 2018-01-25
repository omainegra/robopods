package com.omainegra.robopods.demo

import org.robovm.apple.foundation.NSAutoreleasePool
import org.robovm.apple.uikit.UIApplication
import org.robovm.apple.uikit.UIApplicationDelegateAdapter
import org.robovm.apple.uikit.UIApplicationLaunchOptions

/**
 * Created by omainegra on 1/12/18.
 */

class IosApplication : UIApplicationDelegateAdapter(){

    override fun didFinishLaunching(application: UIApplication?, launchOptions: UIApplicationLaunchOptions?) = true

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            NSAutoreleasePool().use {
                UIApplication.main<UIApplication, IosApplication>(args, null, IosApplication::class.java)
            }
        }
    }
}