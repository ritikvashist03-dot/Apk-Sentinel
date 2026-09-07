plugins {
    `application`
}

java {
    // Compile to the JDK 17 class-file/API surface while using the repository's
    // configured JDK (the supplied JBR is newer but supports --release 17).
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

application {
    mainClass.set("app.apksentinel.receiver.RemoteReceiverMain")
}

tasks.jar {
    manifest { attributes["Main-Class"] = application.mainClass.get() }
}

tasks.test {
    useJUnit()
}
