package com.omainegra.robopods.demo.controllers

import com.omainegra.robopods.lottie.*
import org.robovm.apple.uikit.UIImageView
import org.robovm.apple.uikit.UIViewAutoresizing
import org.robovm.apple.uikit.UIViewAutoresizing.FlexibleHeight
import org.robovm.apple.uikit.UIViewAutoresizing.FlexibleWidth
import org.robovm.apple.uikit.UIViewContentMode
import org.robovm.apple.uikit.UIViewController
import org.robovm.objc.annotation.CustomClass
import org.robovm.objc.annotation.IBOutlet

/**
 * Created by omainegra on 1/12/18.
 */
@CustomClass("LottieViewController")
class LottieViewController : UIViewController() {

    override fun viewDidLoad() {
        super.viewDidLoad()
        // Create Boat Animation
        val boatAnimation = LOTAnimationView.animationNamed("Boat_Loader")
        // Set view to full screen, aspectFill
        boatAnimation.autoresizingMask = UIViewAutoresizing.with(FlexibleWidth, FlexibleHeight)
        boatAnimation.contentMode = UIViewContentMode.ScaleAspectFill
        boatAnimation.frame = view.bounds
        boatAnimation.isLoopAnimation = true
        boatAnimation.play()

        // Add the Animation
        view.addSubview(boatAnimation)
    }
}