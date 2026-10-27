plugins {
    id("com.android.application")
}

// Release builds talk to the portal over https only. There is no public portal yet (README 5b),
// so the address is given at build time: ./gradlew assembleRelease -PportalReleaseBaseUrl=https://...
val releaseBaseUrl: String = providers.gradleProperty("portalReleaseBaseUrl").getOrElse("")
require(releaseBaseUrl.isEmpty() || releaseBaseUrl.startsWith("https://")) {
    "portalReleaseBaseUrl must start with https://"
}

android {
    namespace = "in.ac.nitsri.wifi"
    compileSdk = 37

    defaultConfig {
        applicationId = "in.ac.nitsri.wifi"
        minSdk = 29
        targetSdk = 37
        versionCode = 2
        versionName = "0.6.0"
    }

    buildTypes {
        debug {
            // The lab: `adb reverse tcp:8081 tcp:8081`, the portal stays on the laptop's localhost.
            buildConfigField("String", "PORTAL_BASE_URL", "\"http://127.0.0.1:8081\"")
            buildConfigField("boolean", "ALLOW_LOOPBACK_CLEARTEXT", "true")
        }
        release {
            isMinifyEnabled = false
            buildConfigField("String", "PORTAL_BASE_URL", "\"$releaseBaseUrl\"")
            buildConfigField("boolean", "ALLOW_LOOPBACK_CLEARTEXT", "false")
        }
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            // bcprov, bcutil and bcpkix each have this file (OSGi metadata, not needed on Android)
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }

    lint {
        abortOnError = true
        checkDependencies = false
        // New library versions appear every week; CI must not turn red because of that.
        disable += setOf("GradleDependency", "AndroidGradlePluginVersion", "NewerVersionAvailable")
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("com.google.android.material:material:1.13.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    // PKCS#10 CSR for the EAP-TLS device certificate (approved for stage S6 only). Pulls bcprov and bcutil.
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")

    testImplementation("junit:junit:4.13.2")
    // android.jar has only stubs of org.json for JVM unit tests; this is the same API, for tests only.
    testImplementation("org.json:json:20250517")
}
