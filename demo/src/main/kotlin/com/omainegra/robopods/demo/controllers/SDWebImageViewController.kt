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
class SDWebImageViewController : UIViewController() {

    @IBOutlet lateinit var imageView: UIImageView
    @IBOutlet lateinit var progressView: UIProgressView

    private val imageUrl = "https://static.pexels.com/photos/325045/pexels-photo-325045.jpeg"

    @IBAction fun downloadImage(sender: NSObject){
        UIImageViewExtensions.setImage(
            imageView,
            NSURL(imageUrl),
            UIImage(),
            SDWebImageOptions.ProgressiveDownload,
            { received, total, _ -> NSOperationQueue.getMainQueue().addOperation {
                println("receivedSize = $received, expectedSize = $total")
                val percent = received.toFloat()/total
                progressView.isHidden = false
                progressView.setProgress(percent, true)
            }},
            { _, _, _, _ -> NSOperationQueue.getMainQueue().addOperation {
                println("Completed")
                progressView.isHidden = true
            }}
        )
    }

    @IBAction fun clearCache(sender: NSObject){
        SDWebImageManager.sharedManager().imageCache.removeImageForKey(imageUrl, true, {})
    }
}