package com.omainegra.robopods.demo.controllers

import com.omainegra.robopods.sdwebimage.*
import org.robovm.apple.foundation.NSObject
import org.robovm.apple.foundation.NSOperationQueue
import org.robovm.apple.foundation.NSURL
import org.robovm.apple.uikit.*
import org.robovm.objc.annotation.CustomClass
import org.robovm.objc.annotation.IBAction
import org.robovm.objc.annotation.IBOutlet

/**
 * Created by omainegra on 1/12/18.
 */
@CustomClass("SDWebImageViewController")
class LottieViewController : UIViewController() {

    @IBOutlet lateinit var imageView: UIImageView




}