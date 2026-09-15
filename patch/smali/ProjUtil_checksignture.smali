# Replacement for Lorg/cocos2dx/javascript/ProjUtil;->checksignture(Landroid/content/Context;)Z
# Always report that the APK signature matches the original.
#
# Original: MessageDigest("SHA") over cert bytes -> Base64 -> equals "3jMaDJlNnNJSjitwqDprP53dyxc=".
# A re-signed APK fails this. Forcing true defeats the signature half of the cloner check.
#
# Raw-byte equivalent (code_off 954764, insns at +16):
#   12 10 0f 00   ->  const/4 v0, 1 ; return v0
.method public static checksignture(Landroid/content/Context;)Z
    .registers 7
    const/4 v0, 0x1
    return v0
.end method
