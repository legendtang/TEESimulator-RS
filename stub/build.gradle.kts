plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.ktfmt)
}

android {
    namespace = "org.matrix.stub"
    compileSdk = providers.gradleProperty("tee.compileSdk").map { it.toInt() }.getOrElse(36)
    buildToolsVersion = providers.gradleProperty("tee.buildToolsVersion").getOrElse("36.0.0")
    defaultConfig { minSdk = 29 }

    buildTypes { release { isMinifyEnabled = false } }

    lint { abortOnError = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

dependencies { compileOnly(libs.annotation) }
