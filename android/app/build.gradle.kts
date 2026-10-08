plugins { id("com.android.application") }

android {
    namespace = "io.github.styayur.wutnet"
    compileSdk = 37
    defaultConfig {
        applicationId = "io.github.styayur.wutnet"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1-alpha.1"
    }
    buildFeatures { viewBinding = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
    lint {
        warningsAsErrors = true
        // Pin the documented compatible toolchain; update suggestions are not source defects.
        disable += "AndroidGradlePluginVersion"
    }
}

dependencies { testImplementation("junit:junit:4.13.2") }
