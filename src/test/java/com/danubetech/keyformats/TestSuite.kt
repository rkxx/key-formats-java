package com.danubetech.keyformats

import org.junit.platform.suite.api.SelectPackages
import org.junit.platform.suite.api.Suite

class TestSuite {
    @Suite
    @SelectPackages(
        "com.danubetech.keyformats.crypto",
        "com.danubetech.keyformats.jose",
        "com.danubetech.keyformats.keytypes",
        "com.danubetech.keyformats.provider"
    )
    class TestSuite
}