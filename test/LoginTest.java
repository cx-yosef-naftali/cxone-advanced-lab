import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.junit.Assert;
import static org.mockito.Mockito.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Unit tests for Login class to verify SQL injection vulnerability remediation
 * and proper authentication functionality.
 */
public class LoginTest {

    private HttpServletRequest mockRequest;
    private HttpSession mockSession;
    private Connection mockConnection;
    private PreparedStatement mockStatement;
    private ResultSet mockResultSet;

    @Before
    public void setUp() {
        // Initialize mock objects
        mockRequest = mock(HttpServletRequest.class);
        mockSession = mock(HttpSession.class);
        mockConnection = mock(Connection.class);
        mockStatement = mock(PreparedStatement.class);
        mockResultSet = mock(ResultSet.class);
    }

    @After
    public void tearDown() {
        // Clean up resources
        mockRequest = null;
        mockSession = null;
        mockConnection = null;
        mockStatement = null;
        mockResultSet = null;
    }

    /**
     * Test that normal authentication works with valid credentials
     */
    @Test
    public void testValidAuthentication() throws SQLException {
        // Setup valid user credentials
        when(mockRequest.getParameter("email")).thenReturn("user@example.com");
        when(mockRequest.getParameter("password")).thenReturn("validPassword123");
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockSession.getAttribute("role")).thenReturn("ADMIN");

        // Mock database interactions
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
        when(mockStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true); // User found

        // Verify prepared statement parameters are set correctly
        verify(mockStatement).setString(1, "user@example.com");
        verify(mockStatement).setString(2, "validPassword123");

        // Verify SQL query uses parameterized query (no concatenation)
        String expectedSql = "select * from users where (email = ? and password = ?)";
        verify(mockConnection).prepareStatement(expectedSql);
    }

    /**
     * Test that SQL injection attempts are properly handled and neutralized
     * This test verifies the vulnerability is fixed by ensuring malicious input
     * is treated as parameter data, not executable SQL code.
     */
    @Test
    public void testSqlInjectionPrevention() throws SQLException {
        // Attempt SQL injection via email parameter
        String maliciousEmail = "admin@example.com' OR '1'='1' --";
        String maliciousPassword = "' OR '1'='1' --";

        when(mockRequest.getParameter("email")).thenReturn(maliciousEmail);
        when(mockRequest.getParameter("password")).thenReturn(maliciousPassword);
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockSession.getAttribute("role")).thenReturn("ADMIN");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
        when(mockStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false); // No user found with these exact parameters

        // Verify the malicious input is passed as parameters, not concatenated
        verify(mockStatement).setString(1, maliciousEmail);
        verify(mockStatement).setString(2, maliciousPassword);

        // Verify the SQL structure remains intact (parameterized)
        String expectedSql = "select * from users where (email = ? and password = ?)";
        verify(mockConnection).prepareStatement(expectedSql);

        // Verify no additional SQL commands are executed
        verify(mockStatement, times(1)).executeQuery();
    }

    /**
     * Test SQL injection via password parameter
     */
    @Test
    public void testSqlInjectionViaPassword() throws SQLException {
        String normalEmail = "user@example.com";
        String maliciousPassword = "password'; DROP TABLE users; --";

        when(mockRequest.getParameter("email")).thenReturn(normalEmail);
        when(mockRequest.getParameter("password")).thenReturn(maliciousPassword);
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockSession.getAttribute("role")).thenReturn("ADMIN");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
        when(mockStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        // Verify malicious SQL is treated as a string parameter
        verify(mockStatement).setString(1, normalEmail);
        verify(mockStatement).setString(2, maliciousPassword);

        // Verify prepared statement prevents SQL injection
        String expectedSql = "select * from users where (email = ? and password = ?)";
        verify(mockConnection).prepareStatement(expectedSql);
    }

    /**
     * Test authentication failure with invalid credentials
     */
    @Test
    public void testInvalidAuthentication() throws SQLException {
        when(mockRequest.getParameter("email")).thenReturn("invalid@example.com");
        when(mockRequest.getParameter("password")).thenReturn("wrongpassword");
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockSession.getAttribute("role")).thenReturn("ADMIN");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
        when(mockStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false); // No user found

        // Verify parameters are still set correctly even for invalid credentials
        verify(mockStatement).setString(1, "invalid@example.com");
        verify(mockStatement).setString(2, "wrongpassword");
    }

    /**
     * Test handling of null/empty parameters
     */
    @Test
    public void testNullParameters() throws SQLException {
        when(mockRequest.getParameter("email")).thenReturn(null);
        when(mockRequest.getParameter("password")).thenReturn("");
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockSession.getAttribute("role")).thenReturn("ADMIN");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
        when(mockStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(false);

        // Verify null and empty values are handled as parameters
        verify(mockStatement).setString(1, null);
        verify(mockStatement).setString(2, "");
    }

    /**
     * Test SQL injection with Unicode characters and encoding attacks
     */
    @Test
    public void testAdvancedSqlInjectionAttempts() throws SQLException {
        // Test various advanced SQL injection techniques
        String[] maliciousInputs = {
            "admin'; UNION SELECT * FROM users WHERE '1'='1",
            "admin' UNION SELECT password FROM users WHERE email='admin@example.com' --",
            "admin'; INSERT INTO users VALUES('hacker','hacked'); --",
            "admin' AND (SELECT COUNT(*) FROM users) > 0 --",
            "1' OR '1'='1' UNION SELECT username,password FROM admin_users --"
        };

        for (String maliciousInput : maliciousInputs) {
            when(mockRequest.getParameter("email")).thenReturn(maliciousInput);
            when(mockRequest.getParameter("password")).thenReturn("normalpassword");
            when(mockRequest.getSession()).thenReturn(mockSession);
            when(mockSession.getAttribute("role")).thenReturn("ADMIN");

            when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
            when(mockStatement.executeQuery()).thenReturn(mockResultSet);
            when(mockResultSet.next()).thenReturn(false);

            // Verify each malicious input is treated as a parameter value
            verify(mockStatement, atLeastOnce()).setString(1, maliciousInput);
            verify(mockStatement, atLeastOnce()).setString(2, "normalpassword");
        }
    }

    /**
     * Test that the prepared statement is properly closed for resource management
     */
    @Test
    public void testResourceManagement() throws SQLException {
        when(mockRequest.getParameter("email")).thenReturn("user@example.com");
        when(mockRequest.getParameter("password")).thenReturn("password");
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockSession.getAttribute("role")).thenReturn("ADMIN");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockStatement);
        when(mockStatement.executeQuery()).thenReturn(mockResultSet);
        when(mockResultSet.next()).thenReturn(true);

        // Verify resources are properly closed
        verify(mockStatement).close();
        verify(mockConnection).close();
    }
}