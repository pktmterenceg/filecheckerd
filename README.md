#filecheckerd

is: an improvement to the built-in XProtect malware detection system included with Mac OS X.

because: after reading Sarah Edwards' excellent [presentation](https://www.google.de/url?sa=t&rct=j&q=&esrc=s&source=web&cd=3&cad=rja&uact=8&ved=0CDgQFjAC&url=https%3A%2F%2Fgoogledrive.com%2Fhost%2F0B_qgg13Ykpypekw4d2hwLVJmeDg%2FREMacMalware.pdf&ei=QtDLU4O4PIbqOPmcgMAM&usg=AFQjCNGD3KGsbloxlJUwUq4LKUfyDTi23A&sig2=BSCmmHl_n8WAJejaluQ7jw&bvm=bv.71198958,d.ZWU) on reverse-engineering Mac malware, I became aware of some very obvious shortcomings with XProtect.

--------------------------

###Specifics: 
#### XProtect vs. filecheckerd
XProtect | filecheckerd
---------|-------------
only things downloaded via the quarantine API | any new or changed files
only known Mac malware | all known malware, irrespective of platform[1]
definitions irregularly updated | definitions updated all the time (uses cymru.com API)


* we live in a dual- (or multi-) boot world. To exclude Windows or Linux malware commits the same sort of error ("But the Mac is only 10% of the market!") that people previously used to justify igorning the Mac market. I personally [railed against this kind of thinking](http://en.wikipedia.org/wiki/PocketMac) for years. I used to make my living arguing the other side of that. 

* if you like filecheckerd, please, please consider using the link below to donate to the good folks at cymru.com, upon whose backend API this product relies. 

<form action="https://www.paypal.com/cgi-bin/webscr" method="post">
<input type="hidden" name="cmd" value="_s-xclick">
<input type="hidden" name="hosted_button_id" value="LDJRN3JRGQYDA">
<input type="image" src="https://www.paypal.com/en_US/i/btn/btn_donate_LG.gif" name="submit" alt="PayPal - The safer, easier way to pay online!">
<img alt="" border="0" src="https://www.paypal.com/en_US/i/scr/pixel.gif" width="1" height="1">
</form>

### Technical stuff

* filecheckerd is a GCD-modified (that is, multi-threaded) version of [Amit Singh's excellent /dev/fsevents code](http://osxbook.com/software/fslogger/download/fslogger.c), with some additional bits thrown in.
	* any creation/change/touch/chmod/chown is a trigger
	* files with executable permissions or the "wrong" file extensions (exe, com, js, etc.) are hashed.   
* it also uses DiskAribtration to detect the mounting of volumes to /Volumes. 
	* files on the newly mounted volume are then also recursively hashed. 
* hashes are dispatched to cymru.com's API; matches are quarantined in the currently logged-on user's .Trash folder. 

### Download

ideally, you'd get this from github, build it, and be on your way. 
if that's not your style, though, you can get it pre-built from me at [http://www.gogg.in](http://www.gogg.in). eventually. 

### Issues
* I don't know what will happen if more than one users is logged in w/r/t to where the hashed file will be quarantined. 
* could use some preferences and/or a preference pane. 
* you'll need to download & build the XNU source. http://shantonu.blogspot.de/2012/07/building-xnu-for-os-x-108-mountain-lion.html or http://shantonu.blogspot.de/2013/10/building-xnu-for-os-x-109-mavericks.html for details.


filecheckerd is Copyright 2014 Terence Goggin. Portions are Copyright Amit Singh. 
 * Source released under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.0.
 * See http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt for details.





---------------
[1] seriously. I tested by downloading conficker.
