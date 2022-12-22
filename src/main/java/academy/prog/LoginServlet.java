package academy.prog;

import jakarta.servlet.http.*;
import java.io.IOException;

// Req -> (S -> S) -> jsp

public class LoginServlet extends HttpServlet {
    static final String LOGIN = "admin";
    static final String PASS = "#Admin6789";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String login = request.getParameter("login");
        String password = request.getParameter("password");
        int age = 0;

        HttpSession session = request.getSession(true);
        session.removeAttribute("errorMsg");

        try {
            age = Integer.parseInt(request.getParameter("age"));

            if (login.equals("") || password.equals("")) {
                session.setAttribute("errorMsg", "Input login and password");
            } else if (password.length() < 10) {
                session.setAttribute("errorMsg", "Password must be longer than 10 characters");
            } else if(!password.matches("\\A(?=\\S*?[0-9@#$%^&+=])(?=\\S*?[a-z])(?=\\S*?[A-Z])\\S{10,}\\z")) {
                session.setAttribute("errorMsg", "Password must be at least 10 characters long <br>" +
                        " contain at least one uppercase and lowercase letter <br>" +
                        " contain no spaces");
            } else if  (age < 18) {
                session.setAttribute("errorMsg", "Your age < 18, it's impossible");
            } else if (LOGIN.equals(login) && PASS.equals(password)) {
                session.setAttribute("user_login", login);
            }

        } catch (NumberFormatException e){
            session.setAttribute("errorMsg", "The value of field Age is wrong");
        }

        response.sendRedirect("index.jsp");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String a = request.getParameter("a");
        HttpSession session = request.getSession(false);

        if ("exit".equals(a) && (session != null))
            session.removeAttribute("user_login");
            session.removeAttribute("errorMsg");

        response.sendRedirect("index.jsp");
    }
}
