# Third-party components

First-party WUTNet code remains MIT. Dependency materials retain their own licences.

| Component | Use | Licence |
| --- | --- | --- |
| Gradle wrapper (9.4.1) | Checked-in build bootstrap scripts/JAR | Apache-2.0 |
| Android Gradle plugin (9.2.1) | Build/lint/shrinking tools, not app runtime | Apache-2.0 |
| Kotlin standard library | Kotlin language runtime | Apache-2.0 |
| AndroidX ViewBinding support | Generated Views/XML binding interfaces | Apache-2.0 |
| JUnit 4.13.2 / Hamcrest | JVM tests only, not shipped in the app | EPL-1.0 / BSD-3-Clause |

No third-party HTTP library, analytics SDK, ad SDK, account service, Compose or
cross-platform application framework is used. Android SDK/system APIs are supplied
by the platform and are governed by their upstream licences/SDK terms.

Gradle wrapper source: https://github.com/gradle/gradle/tree/v9.4.1/gradle/wrapper
(copyright Gradle contributors; notices remain in the upstream launcher scripts).
Wrapper JAR and distribution checksums are verified against downloads.gradle.org;
the distribution checksum is pinned in `gradle-wrapper.properties`.

Upstream licences: [Gradle](https://github.com/gradle/gradle/blob/v9.4.1/LICENSE),
[Kotlin](https://github.com/JetBrains/kotlin/blob/master/license/LICENSE.txt),
[AndroidX](https://android.googlesource.com/platform/frameworks/support/+/androidx-main/LICENSE.txt),
[JUnit](https://github.com/junit-team/junit4/blob/main/LICENSE-junit.txt).
The Apache-2.0 licence is included in `android/gradle/LICENSE`; app runtime notices
are packaged in `res/raw/third_party_notices.txt`.
