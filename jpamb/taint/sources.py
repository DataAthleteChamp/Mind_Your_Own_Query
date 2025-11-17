"""
jpamb.taint.sources

Source and sink detection for SQL injection analysis.

Sources are where untrusted data originates (e.g., HTTP requests).
Sinks are where untrusted data becomes dangerous (e.g., SQL execution).
"""

from typing import Set
from dataclasses import dataclass


# Define untrusted sources (where taint originates)
UNTRUSTED_SOURCES: Set[str] = {
    # HTTP Servlet (most common)
    "javax.servlet.http.HttpServletRequest.getParameter",
    "javax.servlet.http.HttpServletRequest.getHeader",
    "javax.servlet.http.HttpServletRequest.getQueryString",
    "javax.servlet.ServletRequest.getInputStream",
    "javax.servlet.ServletRequest.getReader",
    # File I/O
    "java.io.BufferedReader.readLine",
    "java.io.FileInputStream.read",
    "java.io.FileReader.read",
    # Network
    "java.net.URLConnection.getInputStream",
    "java.net.Socket.getInputStream",
    "java.net.HttpURLConnection.getInputStream",
    # System
    "java.lang.System.getenv",
    "java.lang.System.getProperty",
    # Console
    "java.util.Scanner.nextLine",
    "java.util.Scanner.next",
    "java.io.Console.readLine",
}

# Define dangerous sinks (where tainted data is dangerous)
SQL_SINKS: Set[str] = {
    # JDBC Statement (vulnerable to SQLi)
    "java.sql.Statement.execute",
    "java.sql.Statement.executeQuery",
    "java.sql.Statement.executeUpdate",
    "java.sql.Statement.executeLargeUpdate",
    "java.sql.Statement.addBatch",
    # Connection.prepareStatement with tainted SQL is vulnerable
    "java.sql.Connection.prepareStatement",
    "java.sql.Connection.prepareCall",
    # Note: PreparedStatement.setString() is SAFE (parameterized)
    # so we don't include it as a sink
}


@dataclass
class SourceSinkDetector:
    """
    Detects sources and sinks in method calls.

    This class helps identify:
    - Sources: Where untrusted data enters the program
    - Sinks: Where untrusted data can cause harm
    """

    sources: Set[str]
    sinks: Set[str]

    @classmethod
    def default(cls) -> "SourceSinkDetector":
        """Create detector with default SQL injection sources/sinks"""
        return cls(UNTRUSTED_SOURCES, SQL_SINKS)

    def is_source(self, method_name: str) -> bool:
        """
        Check if method is an untrusted source.

        Args:
            method_name: Fully qualified method name

        Returns:
            True if this method returns untrusted data

        Example:
            >>> detector = SourceSinkDetector.default()
            >>> detector.is_source("javax.servlet.http.HttpServletRequest.getParameter")
            True
            >>> detector.is_source("java.lang.String.length")
            False
        """
        return any(source in method_name for source in self.sources)

    def is_sink(self, method_name: str) -> bool:
        """
        Check if method is a dangerous sink.

        Args:
            method_name: Fully qualified method name

        Returns:
            True if tainted data to this method is dangerous

        Example:
            >>> detector = SourceSinkDetector.default()
            >>> detector.is_sink("java.sql.Statement.execute")
            True
            >>> detector.is_sink("java.lang.System.out.println")
            False
        """
        return any(sink in method_name for sink in self.sinks)

    def get_source_type(self, method_name: str) -> str:
        """
        Identify what type of source this is.

        Args:
            method_name: Fully qualified method name

        Returns:
            String describing source type

        Example:
            >>> detector = SourceSinkDetector.default()
            >>> detector.get_source_type("javax.servlet.http.HttpServletRequest.getParameter")
            'http_request'
        """
        # Define source type mappings (pattern -> type)
        source_patterns = [
            (["HttpServletRequest", "ServletRequest"], "http_request"),
            (["File", "Reader"], "file_io"),
            (["Socket", "URLConnection"], "network"),
            (["System.getenv", "System.getProperty"], "system_property"),
            (["Scanner", "Console"], "console_input"),
        ]

        # Check each pattern
        for patterns, source_type in source_patterns:
            if any(pattern in method_name for pattern in patterns):
                return source_type

        return "external_input"

    def get_sink_type(self, method_name: str) -> str:
        """
        Identify what type of sink this is.

        Args:
            method_name: Fully qualified method name

        Returns:
            String describing sink type

        Example:
            >>> detector = SourceSinkDetector.default()
            >>> detector.get_sink_type("java.sql.Statement.execute")
            'sql_execution'
        """
        if "Statement" in method_name or "Connection.prepare" in method_name:
            return "sql_execution"
        else:
            return "unknown_sink"
