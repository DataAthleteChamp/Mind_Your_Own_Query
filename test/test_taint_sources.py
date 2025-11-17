"""
Tests for jpamb.taint.sources module
"""

import pytest
from jpamb.taint.sources import SourceSinkDetector, UNTRUSTED_SOURCES, SQL_SINKS


class TestSourceDetection:
    """Test source detection"""

    def test_http_parameter_is_source(self):
        """HttpServletRequest.getParameter is a source"""
        detector = SourceSinkDetector.default()
        assert detector.is_source(
            "javax.servlet.http.HttpServletRequest.getParameter"
        )

    def test_file_read_is_source(self):
        """File reading methods are sources"""
        detector = SourceSinkDetector.default()
        assert detector.is_source("java.io.BufferedReader.readLine")
        assert detector.is_source("java.io.FileReader.read")

    def test_network_is_source(self):
        """Network methods are sources"""
        detector = SourceSinkDetector.default()
        assert detector.is_source("java.net.URLConnection.getInputStream")
        assert detector.is_source("java.net.Socket.getInputStream")

    def test_system_property_is_source(self):
        """System.getenv and getProperty are sources"""
        detector = SourceSinkDetector.default()
        assert detector.is_source("java.lang.System.getenv")
        assert detector.is_source("java.lang.System.getProperty")

    def test_safe_method_not_source(self):
        """Regular methods are not sources"""
        detector = SourceSinkDetector.default()
        assert not detector.is_source("java.lang.String.length")
        assert not detector.is_source("java.lang.Math.abs")


class TestSinkDetection:
    """Test sink detection"""

    def test_statement_execute_is_sink(self):
        """Statement.execute methods are sinks"""
        detector = SourceSinkDetector.default()
        assert detector.is_sink("java.sql.Statement.execute")
        assert detector.is_sink("java.sql.Statement.executeQuery")
        assert detector.is_sink("java.sql.Statement.executeUpdate")

    def test_prepare_statement_is_sink(self):
        """Connection.prepareStatement is a sink (for tainted SQL)"""
        detector = SourceSinkDetector.default()
        assert detector.is_sink("java.sql.Connection.prepareStatement")
        assert detector.is_sink("java.sql.Connection.prepareCall")

    def test_safe_method_not_sink(self):
        """Regular methods are not sinks"""
        detector = SourceSinkDetector.default()
        assert not detector.is_sink("java.lang.System.out.println")
        assert not detector.is_sink("java.lang.String.concat")


class TestSourceTypeIdentification:
    """Test source type identification"""

    def test_http_source_type(self):
        """Identify HTTP request sources"""
        detector = SourceSinkDetector.default()
        assert detector.get_source_type(
            "javax.servlet.http.HttpServletRequest.getParameter"
        ) == "http_request"

    def test_file_source_type(self):
        """Identify file I/O sources"""
        detector = SourceSinkDetector.default()
        assert detector.get_source_type(
            "java.io.FileReader.read"
        ) == "file_io"

    def test_network_source_type(self):
        """Identify network sources"""
        detector = SourceSinkDetector.default()
        assert detector.get_source_type(
            "java.net.Socket.getInputStream"
        ) == "network"

    def test_system_property_source_type(self):
        """Identify system property sources"""
        detector = SourceSinkDetector.default()
        assert detector.get_source_type(
            "java.lang.System.getenv"
        ) == "system_property"

    def test_console_source_type(self):
        """Identify console input sources"""
        detector = SourceSinkDetector.default()
        assert detector.get_source_type(
            "java.util.Scanner.nextLine"
        ) == "console_input"


class TestSinkTypeIdentification:
    """Test sink type identification"""

    def test_sql_execution_sink_type(self):
        """Identify SQL execution sinks"""
        detector = SourceSinkDetector.default()
        assert detector.get_sink_type(
            "java.sql.Statement.execute"
        ) == "sql_execution"


class TestCustomSourcesAndSinks:
    """Test creating detector with custom sources/sinks"""

    def test_custom_sources(self):
        """Create detector with custom sources"""
        custom_sources = {"my.custom.Source.getData"}
        custom_sinks = {"my.custom.Sink.processData"}
        detector = SourceSinkDetector(custom_sources, custom_sinks)

        assert detector.is_source("my.custom.Source.getData")
        assert not detector.is_source("java.io.FileReader.read")

    def test_custom_sinks(self):
        """Create detector with custom sinks"""
        custom_sources = {"my.custom.Source.getData"}
        custom_sinks = {"my.custom.Sink.processData"}
        detector = SourceSinkDetector(custom_sources, custom_sinks)

        assert detector.is_sink("my.custom.Sink.processData")
        assert not detector.is_sink("java.sql.Statement.execute")


class TestPartialMatching:
    """Test partial matching of method names"""

    def test_partial_match_source(self):
        """Sources are matched by substring"""
        detector = SourceSinkDetector.default()
        # Full method signature should match
        assert detector.is_source(
            "full.package.javax.servlet.http.HttpServletRequest.getParameter"
        )

    def test_partial_match_sink(self):
        """Sinks are matched by substring"""
        detector = SourceSinkDetector.default()
        # Full method signature should match
        assert detector.is_sink(
            "full.package.java.sql.Statement.execute"
        )


class TestConstants:
    """Test the constant sets"""

    def test_untrusted_sources_set(self):
        """UNTRUSTED_SOURCES is a set"""
        assert isinstance(UNTRUSTED_SOURCES, set)
        assert len(UNTRUSTED_SOURCES) > 0

    def test_sql_sinks_set(self):
        """SQL_SINKS is a set"""
        assert isinstance(SQL_SINKS, set)
        assert len(SQL_SINKS) > 0

    def test_common_sources_present(self):
        """Check that common sources are in the set"""
        assert any("HttpServletRequest.getParameter" in s for s in UNTRUSTED_SOURCES)
        assert any("BufferedReader.readLine" in s for s in UNTRUSTED_SOURCES)

    def test_common_sinks_present(self):
        """Check that common sinks are in the set"""
        assert any("Statement.execute" in s for s in SQL_SINKS)
        assert any("Connection.prepareStatement" in s for s in SQL_SINKS)
