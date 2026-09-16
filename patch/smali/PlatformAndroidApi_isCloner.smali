# Replacement for Lorg/cocos2dx/javascript/PlatformAndroidApi;->isCloner()I
# The JS bridge calls this (callPlatformApi("isCloner","()I")). Force it to 0.
#
# Raw-byte equivalent (code_off 951344, insns at +16):
#   12 00 0f 00   ->  const/4 v0, 0 ; return v0
.method public static isCloner()I
    .registers 2
    const/4 v0, 0x0
    return v0
.end method
