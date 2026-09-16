# Replacement for Lorg/cocos2dx/javascript/ProjUtil;->isCloner(Landroid/content/Context;)Z
# Makes the anti-tamper "cloner" check always report NOT-a-cloner.
#
# Original behaviour: computes base64(SHA1(signing-cert)) and compares it to the
# hardcoded "3jMaDJlNnNJSjitwqDprP53dyxc=", plus a /data/data/<pkg>/files path check.
# After re-signing (any SSL-bypass patcher), the cert hash no longer matches ->
# isCloner()=true -> "Share Slots can not run at this mode!".
#
# Raw-byte equivalent (applied in classes.dex.patched at code_off 955000, insns at +16):
#   12 00 0f 00   ->  const/4 v0, 0 ; return v0
.method public static isCloner(Landroid/content/Context;)Z
    .registers 8
    const/4 v0, 0x0
    return v0
.end method
