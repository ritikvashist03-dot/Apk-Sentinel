# ApkSigningInspector reads optional scheme booleans reflectively to stay
# compatible with the pinned build-tools result surface. Preserve only those
# zero-argument accessors in minified release builds.
-keepclassmembers class com.android.apksig.ApkVerifier$Result {
    boolean isVerifiedUsing*();
}
