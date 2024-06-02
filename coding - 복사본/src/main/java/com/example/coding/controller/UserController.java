package com.example.coding.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringWriter;
import java.net.URI;
import java.sql.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.InputStream;

import javax.servlet.http.HttpSession;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Controller
public class UserController {
    // JDBC URL, 사용자 이름, 비밀번호
    private static final String JDBC_URL = "jdbc:mysql://localhost:3306/coding";
    private static final String DB_USERNAME = "root";
    private static final String DB_PASSWORD = "mic2019";

    public static void contestInfo(Model model, HttpSession session) {
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        Statement statement = null;

        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 데이터베이스 연결
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null){
                System.out.println("성공");
                // 쿼리 실행을 위한 Statement 객체 생성
                statement = connection.createStatement();
                // SQL 쿼리 실행
                String sql = "SELECT * FROM contests";
                ResultSet resultSet = statement.executeQuery(sql);

                List<String> list = new ArrayList<String>();

                // 결과 처리
                while (resultSet.next()) {
                    list.add(resultSet.getString("contest_name"));
                }

                session.setAttribute("contests", list);
                model.addAttribute("contests", list);

                // 리소스 해제
                resultSet.close();
                statement.close();
                connection.close();
                System.out.println("종료 !");
            } else{System.out.println("실패");}
        } catch (SQLException e) {
            System.out.println( "[SQL 오류] > " + e.getMessage() );
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println( "[클래스 오류]" + e.getMessage() );
            e.printStackTrace();
        } finally {
            try {
                if (statement != null) statement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        return;
    }

    public static boolean containsSpecialCharacters(String input) {
        Pattern pattern = Pattern.compile("[^a-zA-Z0-9\\s]");
        Matcher matcher = pattern.matcher(input);
        return matcher.find();
    }

    public static boolean containsAlphabet(String input) {
        Pattern pattern = Pattern.compile("[a-zA-Z]");
        Matcher matcher = pattern.matcher(input);
        return matcher.find();
    }

    public static boolean containsNumber(String input) {
        Pattern pattern = Pattern.compile("[0-9]");
        Matcher matcher = pattern.matcher(input);
        return matcher.find();
    }

    @PostMapping("/register")
    public String register(@RequestParam("username") String name, @RequestParam("ID") String id, @RequestParam("password") String pw, @RequestParam("password2") String pw2, @RequestParam("phoneNumber") String tell, Model model) {
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        Statement statement = null;
        PreparedStatement preparedStatement = null;

        if (!(pw.equals(pw2))){
            model.addAttribute("error", "비밀번호가 일치하지 않습니다.");
            return "register";
        }

        boolean hasSpecialCharacters = containsSpecialCharacters(pw);
        if (hasSpecialCharacters) {
            System.out.println("The string contains special characters.");
        } else {
            model.addAttribute("error", "비밀번호에 특수문자 하나 이상 포함해야합니다.");
            return "register";
        }
        boolean hasAlphabet = containsAlphabet(pw);
        if (hasAlphabet) {
            System.out.println("The string contains special characters.");
        } else {
            model.addAttribute("error", "비밀번호에 알파벳 하나 이상 포함해야합니다.");
            return "register";
        }
        boolean hasNumber = containsNumber(pw);
        if (hasNumber) {
            System.out.println("The string contains special characters.");
        } else {
            model.addAttribute("error", "비밀번호에 숫자 하나 이상 포함해야합니다.");
            return "register";
        }

        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 데이터베이스 연결
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null){
                System.out.println("성공");
                // 데이터 추가
                String sql1 = "INSERT INTO users (user_name, user_id, user_pw, user_tell) VALUES (?, ?, ?, ?)";

                // PreparedStatement 객체 생성
                preparedStatement = connection.prepareStatement(sql1);

                // 값 설정
                preparedStatement.setString(1, name);
                preparedStatement.setString(2, id);
                preparedStatement.setString(3, pw);
                preparedStatement.setString(4, tell);

                // SQL 문 실행
                int rowsInserted = preparedStatement.executeUpdate();
                if (rowsInserted > 0) {
                    System.out.println("A new user was inserted successfully!");
                }

                // 쿼리 실행을 위한 Statement 객체 생성
                statement = connection.createStatement();

                statement.close();
                connection.close();
                System.out.println("종료 !");
            } else{System.out.println("실패");}
        } catch (SQLException e) {
            System.out.println( "[SQL 오류] > " + e.getMessage() );
            e.printStackTrace();
            model.addAttribute("error", "중복된 아이디!");
            return "register";
        } catch (ClassNotFoundException e) {
            System.out.println( "[클래스 오류]" + e.getMessage() );
            e.printStackTrace();
        } finally {
            try {
                if (statement != null) statement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam("ID") String id, @RequestParam("password") String pw, HttpSession session, Model model) {
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null) {
                String sql = "SELECT * FROM users WHERE user_id = ? AND user_pw = ?";
                preparedStatement = connection.prepareStatement(sql);
                preparedStatement.setString(1, id);
                preparedStatement.setString(2, pw);
                resultSet = preparedStatement.executeQuery();

                if (resultSet.next()) {
                    String username = resultSet.getString("user_name");
                    String userid = resultSet.getString("user_id");
                    String usertell = resultSet.getString("user_tell");
                    session.setAttribute("username", username);
                    session.setAttribute("userid", userid);
                    session.setAttribute("usertell", usertell);
                    return "redirect:/home";
                } else {
                    model.addAttribute("error", "잘못된 사용자명 또는 비밀번호입니다.");
                    return "login";
                }
            }
        } catch (SQLException | ClassNotFoundException e) {
            e.printStackTrace();
            model.addAttribute("error", "요청을 처리하는 동안 오류가 발생했습니다.");
            return "login";
        } finally {
            try {
                if (resultSet != null) resultSet.close();
                if (preparedStatement != null) preparedStatement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        model.addAttribute("error", "잘못된 사용자명 또는 비밀번호입니다.");
        return "login";
    }

    @PostMapping("/changepassword")
    public String changePassword(@RequestParam("ID") String id, @RequestParam("currentPassword") String currentPassword, @RequestParam("newPassword") String newPassword, @RequestParam("confirmNewPassword") String confirmNewPassword, Model model) {
        if (!newPassword.equals(confirmNewPassword)) {
            model.addAttribute("error", "새로운 비밀번호가 일치하지 않습니다.");
            return "change_password";
        }

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        boolean hasSpecialCharacters = containsSpecialCharacters(newPassword);
        if (hasSpecialCharacters) {
            System.out.println("The string contains special characters.");
        } else {
            model.addAttribute("error", "비밀번호에 특수문자 하나 이상 포함해야합니다.");
            return "change_password";
        }
        boolean hasAlphabet = containsAlphabet(newPassword);
        if (hasAlphabet) {
            System.out.println("The string contains special characters.");
        } else {
            model.addAttribute("error", "비밀번호에 알파벳 하나 이상 포함해야합니다.");
            return "change_password";
        }
        boolean hasNumber = containsNumber(newPassword);
        if (hasNumber) {
            System.out.println("The string contains special characters.");
        } else {
            model.addAttribute("error", "비밀번호에 숫자 하나 이상 포함해야합니다.");
            return "change_password";
        }

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            // 현재 비밀번호 확인
            String checkPasswordQuery = "SELECT user_pw FROM users WHERE user_id = ?";
            preparedStatement = connection.prepareStatement(checkPasswordQuery);
            preparedStatement.setString(1, id);
            resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                String storedPassword = resultSet.getString("user_pw");
                if (!storedPassword.equals(currentPassword)) {
                    model.addAttribute("error", "잘못된 사용자명 또는 비밀번호입니다.");
                    return "change_password";
                }
            } else {
                model.addAttribute("error", "잘못된 사용자명 또는 비밀번호입니다.");
                return "change_password";
            }

            // 비밀번호 업데이트
            String updatePasswordQuery = "UPDATE users SET user_pw = ? WHERE user_id = ?";
            preparedStatement = connection.prepareStatement(updatePasswordQuery);
            preparedStatement.setString(1, newPassword);
            preparedStatement.setString(2, id);
            int rowsUpdated = preparedStatement.executeUpdate();

            if (rowsUpdated > 0) {
                return "login";
            } else {
                model.addAttribute("error", "변경에 실패했습니다.");
                return "change_password";
            }
        } catch (SQLException | ClassNotFoundException e) {
            e.printStackTrace();
            model.addAttribute("error", "서버 오류");
            return "change_password";
        } finally {
            try {
                if (resultSet != null) resultSet.close();
                if (preparedStatement != null) preparedStatement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    @PostMapping("/makecontest")
    public String makecontest(@RequestParam("ID") String id, @RequestParam("title") String title, @RequestParam("password") String pw, @RequestParam("password2") String pw2, @RequestParam("description") String description, Model model, HttpSession session) {
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        Statement statement = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        String userid = (String) session.getAttribute("userid");

        if (!(id.equals(userid))){
            model.addAttribute("error", "본인의 아이디가 아닙니다.");
            return "make_contest";
        }

        if (!(pw.equals(pw2))){
            model.addAttribute("error", "비밀번호가 일치하지 않습니다.");
            return "make_contest";
        }

        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 데이터베이스 연결
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null){
                System.out.println("성공");
                // 데이터 추가
                String sql1 = "INSERT INTO contests (user_id, contest_name, description, contest_pw) VALUES (?, ?, ?, ?)";

                // PreparedStatement 객체 생성
                preparedStatement = connection.prepareStatement(sql1);

                // 값 설정
                preparedStatement.setString(1, id);
                preparedStatement.setString(2, title);
                preparedStatement.setString(3, description);
                preparedStatement.setString(4, pw);

                // SQL 문 실행
                int rowsInserted = preparedStatement.executeUpdate();
                if (rowsInserted > 0) {
                    System.out.println("A new contest was inserted successfully!");
                }

                String sql = "SELECT * FROM contests WHERE user_id = ? AND contest_name = ?";

                preparedStatement = connection.prepareStatement(sql);
                preparedStatement.setString(1, id);
                preparedStatement.setString(2, title);
                resultSet = preparedStatement.executeQuery();

                if (resultSet.next()) {
                    String contestid = resultSet.getString("contest_id");
                    String contestname = resultSet.getString("contest_name");
                    session.setAttribute("contestid", contestid);
                    session.setAttribute("contestname", contestname);
                    return "redirect:/makeproblem";
                }

                // 쿼리 실행을 위한 Statement 객체 생성
                statement = connection.createStatement();

                statement.close();
                connection.close();
                System.out.println("종료 !");
            } else{System.out.println("실패");}
        } catch (SQLException e) {
            System.out.println( "[SQL 오류] > " + e.getMessage() );
            e.printStackTrace();
            model.addAttribute("error", "이미 지정된 대회명입니다.");
            return "make_contest";
        } catch (ClassNotFoundException e) {
            System.out.println( "[클래스 오류]" + e.getMessage() );
            e.printStackTrace();
        } finally {
            try {
                if (statement != null) statement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        model.addAttribute("error", "이미 지정된 대회명입니다.");
        return "make_contest";
    }

    @PostMapping("/makeproblem")
    public String makeproblem(@RequestParam("title") String title, @RequestParam("description") String description, @RequestParam("inputdescription") String inputdescription, @RequestParam("outputdescription") String outputdescription, @RequestParam("inputexample") String inputexample, @RequestParam("outputexample") String outputexample, @RequestParam("operation") String operation, Model model, HttpSession session) {
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        Statement statement = null;
        PreparedStatement preparedStatement = null;

        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 데이터베이스 연결
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null){
                System.out.println("성공");
                // 데이터 추가
                String sql1 = "INSERT INTO problems (contest_id, problem_name, description, input_description, output_description, example_input,  example_output) VALUES (?, ?, ?, ?, ?, ?, ?)";

                // PreparedStatement 객체 생성
                preparedStatement = connection.prepareStatement(sql1);

                String contestid = (String) session.getAttribute("contestid");

                // 값 설정
                preparedStatement.setString(1, contestid);
                preparedStatement.setString(2, title);
                preparedStatement.setString(3, description);
                preparedStatement.setString(4, inputdescription);
                preparedStatement.setString(5, outputdescription);
                preparedStatement.setString(6, inputexample);
                preparedStatement.setString(7, outputexample);

                // SQL 문 실행
                int rowsInserted = preparedStatement.executeUpdate();
                if (rowsInserted > 0) {
                    System.out.println("A new problem was inserted successfully!");
                }

                // 쿼리 실행을 위한 Statement 객체 생성
                statement = connection.createStatement();

                statement.close();
                connection.close();
                System.out.println("종료 !");
            } else{System.out.println("실패");}
        } catch (SQLException e) {
            System.out.println( "[SQL 오류] > " + e.getMessage() );
            e.printStackTrace();
            model.addAttribute("error", "이미 지정된 문제 이름입니다.");
            return "redirect:/makeproblem";
        } catch (ClassNotFoundException e) {
            System.out.println( "[클래스 오류]" + e.getMessage() );
            e.printStackTrace();
        } finally {
            try {
                if (statement != null) statement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }

        if (operation.equals("문제 더 만들기")) {
            return "redirect:/makeproblem";
        } else if (operation.equals("대회 완성")) {
            return "redirect:/home";
        }

        model.addAttribute("error", "이미 지정된 문제 이름입니다.");
        return "redirect:/makeproblem";
    }

    @PostMapping("/opencontest")
    public String opencontest(@RequestParam("contest") String contest, Model model, HttpSession session){
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        Statement statement = null;
        PreparedStatement preparedStatement = null;

        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 데이터베이스 연결
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null){
                System.out.println("성공");
                // 쿼리 실행을 위한 Statement 객체 생성
                statement = connection.createStatement();

                @SuppressWarnings("unchecked")
                List<String> list = (List<String>) session.getAttribute("contests");

                int index = list.indexOf(contest);

                String sql = "SELECT * FROM problems WHERE contest_id = ?";
                preparedStatement = connection.prepareStatement(sql);
                preparedStatement.setString(1, String.valueOf(index+1));
                ResultSet resultSet = preparedStatement.executeQuery();

                List<String> list2 = new ArrayList<String>();

                // 결과 처리
                while (resultSet.next()) {
                    list2.add(resultSet.getString("problem_name"));
                }

                session.setAttribute("problems", list2);

                // 리소스 해제
                resultSet.close();
                statement.close();
                connection.close();
                System.out.println("종료 !");

                return "redirect:/opencontest";
            } else{System.out.println("실패");}
        } catch (SQLException e) {
            System.out.println( "[SQL 오류] > " + e.getMessage() );
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println( "[클래스 오류]" + e.getMessage() );
            e.printStackTrace();
        } finally {
            try {
                if (statement != null) statement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }


        return "/home";
    }

    @PostMapping("/openproblem")
    public String openproblem(@RequestParam("problem") String problem, Model model, HttpSession session){
        // Connection, Statement, preparedStatement 객체를 선언
        Connection connection = null;
        Statement statement = null;
        PreparedStatement preparedStatement = null;
        
        session.removeAttribute("error");
        session.removeAttribute("message");
        session.removeAttribute("result");

        try {
            // JDBC 드라이버 로드
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 데이터베이스 연결
            connection = DriverManager.getConnection(JDBC_URL, DB_USERNAME, DB_PASSWORD);

            if (connection != null){
                System.out.println("성공");
                // 쿼리 실행을 위한 Statement 객체 생성
                statement = connection.createStatement();

                String sql = "SELECT * FROM problems WHERE problem_name = ?";
                preparedStatement = connection.prepareStatement(sql);
                preparedStatement.setString(1, problem);
                ResultSet resultSet = preparedStatement.executeQuery();

                if (resultSet.next()) {
                    String problemname = resultSet.getString("problem_name");
                    String contestid = resultSet.getString("contest_id");
                    String description = resultSet.getString("description");
                    String inputdescription = resultSet.getString("input_description");
                    String outputdescription = resultSet.getString("output_description");
                    String exampleinput = resultSet.getString("example_input");
                    String exampleoutput = resultSet.getString("example_output");
                    session.setAttribute("problemname", problemname);
                    session.setAttribute("contestid", contestid);
                    session.setAttribute("description", description);
                    session.setAttribute("inputdescription", inputdescription);
                    session.setAttribute("outputdescription", outputdescription);
                    session.setAttribute("exampleinput", exampleinput);
                    session.setAttribute("exampleoutput", exampleoutput);
                    return "redirect:/openproblem";
                }

                // 리소스 해제
                resultSet.close();
                statement.close();
                connection.close();
                System.out.println("종료 !");
                model.addAttribute("error", "잘못된 문제명입니다.");
                return "open_contest";
            } else{System.out.println("실패");}
        } catch (SQLException e) {
            System.out.println( "[SQL 오류] > " + e.getMessage() );
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println( "[클래스 오류]" + e.getMessage() );
            e.printStackTrace();
        } finally {
            try {
                if (statement != null) statement.close();
                if (connection != null) connection.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }


        return "/home";
    }

    @PostMapping("/submitCode")
    public String submitCode(@RequestParam("code") String code, Model model, HttpSession session){

        // 모든 기존 모델 속성 초기화
        session.removeAttribute("error");
        session.removeAttribute("message");
        session.removeAttribute("result");
                
        String input = (String) session.getAttribute("exampleinput");

        // 코드 컴파일 및 실행
        String result = compileAndRunCode(code, input, session);

        // 결과를 모델에 추가
        session.setAttribute("result", result);

        System.out.println(code);
        return "redirect:/openproblem";
    }

    private String compileAndRunCode(String code, String input, HttpSession session) {
        try {
            // Java Compiler API 사용
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
            StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, null, null);

            // 메모리 내에 소스 코드 저장
            JavaFileObject javaFileObject = new InMemoryJavaFileObject("Main", code);
            Iterable<? extends JavaFileObject> compilationUnits = Collections.singletonList(javaFileObject);

            // 컴파일
            StringWriter compilationOutput = new StringWriter();
            JavaCompiler.CompilationTask task = compiler.getTask(compilationOutput, fileManager, diagnostics, null, null, compilationUnits);
            boolean success = task.call();
            if (!success) {
                StringBuilder errorMsg = new StringBuilder("Compilation Error:\n");
                for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                    errorMsg.append(diagnostic.getMessage(null)).append("\n");
                }
                return errorMsg.toString();
            }

            // 파일 매니저 닫기
            fileManager.close();

            // 컴파일된 클래스 로드 및 실행
            DynamicClassLoader classLoader = new DynamicClassLoader();
            Class<?> clazz = classLoader.loadClass("Main");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(outputStream);
            InputStream inputStream = new ByteArrayInputStream(input.getBytes());

            // 기존 System.out, System.in 백업
            PrintStream originalOut = System.out;
            InputStream originalIn = System.in;

            // System.out, System.in 리디렉션
            System.setOut(printStream);
            System.setIn(inputStream);

            // 클래스의 main 메서드 실행
            try {
                clazz.getMethod("main", String[].class).invoke(null, (Object) new String[]{});
            } finally {
                // 원래의 System.out, System.in 복원
                System.setOut(originalOut);
                System.setIn(originalIn);
            }

            // 실행 결과 읽기
            String output = outputStream.toString();
            String expectedOutput = (String) session.getAttribute("exampleoutput");
            return output.trim().equals(expectedOutput.trim()) ? "Correct" : "Incorrect";

        } catch (Exception e) {
            e.printStackTrace();
            return "Execution Error: " + e.getMessage();
        }
    }

    // 메모리 내에서 소스 파일을 표현하는 클래스
    class InMemoryJavaFileObject extends SimpleJavaFileObject {
        private final String sourceCode;

        public InMemoryJavaFileObject(String className, String sourceCode) {
            super(URI.create("string:///" + className.replace('.', '/') + Kind.SOURCE.extension), Kind.SOURCE);
            this.sourceCode = sourceCode;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return sourceCode;
        }
    }

    // 메모리 내에서 클래스를 로드하는 클래스 로더
    class DynamicClassLoader extends ClassLoader {
        private final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        private final StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null);

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            InMemoryJavaFileObject javaFileObject = new InMemoryJavaFileObject(name, "");
            Iterable<? extends JavaFileObject> compilationUnits = Collections.singletonList(javaFileObject);

            // 메모리 내에서 컴파일된 클래스의 바이트코드 저장
            ByteArrayOutputStream byteCode = new ByteArrayOutputStream();

            // 컴파일
            JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, null, null, null, compilationUnits);
            boolean success = task.call();
            if (!success) {
                throw new ClassNotFoundException("Compilation failed.");
            }

            byte[] bytes = byteCode.toByteArray();
            return defineClass(name, bytes, 0, bytes.length);
        }
    }


    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/home";
    }

    @GetMapping("/profile")
    public String profile(Model model, HttpSession session) {
        String username = (String) session.getAttribute("username");
        String userid = (String) session.getAttribute("userid");
        String usertell = (String) session.getAttribute("usertell");
        model.addAttribute("username", username);
        model.addAttribute("userid", userid);
        model.addAttribute("usertell", usertell);
        return "profile";
    }

    @GetMapping("/makeproblem")
    public String makeproblem(Model model, HttpSession session) {
        String contestid = (String) session.getAttribute("contestid");
        String contestname = (String) session.getAttribute("contestname");
        model.addAttribute("contestid", contestid);
        model.addAttribute("contestname", contestname);
        return "make_problem";
    }

    @GetMapping("/opencontest")
    public String opencontest(Model model, HttpSession session) {
        @SuppressWarnings("unchecked")
        List<String> problems = (List<String>) session.getAttribute("problems");
        String username = (String) session.getAttribute("username");
        model.addAttribute("username", username);
        model.addAttribute("problems", problems);
        return "open_contest";
    }

    @GetMapping("/openproblem")
    public String openproblem(Model model, HttpSession session) {
        String problemname = (String) session.getAttribute("problemname");
        String contestid = (String) session.getAttribute("contestid");
        String description = (String) session.getAttribute("description");
        String inputdescription = (String) session.getAttribute("inputdescription");
        String outputdescription = (String) session.getAttribute("outputdescription");
        String exampleinput = (String) session.getAttribute("exampleinput");
        String exampleoutput = (String) session.getAttribute("exampleoutput");
        String username = (String) session.getAttribute("username");
        String error = (String) session.getAttribute("error");
        String message = (String) session.getAttribute("message");
        String result = (String) session.getAttribute("result");
        model.addAttribute("problemname", problemname);
        model.addAttribute("contestid", contestid);
        model.addAttribute("description", description);
        model.addAttribute("inputdescription", inputdescription);
        model.addAttribute("outputdescription", outputdescription);
        model.addAttribute("exampleinput", exampleinput);
        model.addAttribute("exampleoutput", exampleoutput);
        model.addAttribute("username", username);
        model.addAttribute("error", error);
        model.addAttribute("message", message);
        model.addAttribute("result", result);
        return "open_problem";
    }

    @GetMapping("/home")
    public String home(Model model, HttpSession session) {
        contestInfo(model, session);
        String username = (String) session.getAttribute("username");
        String userid = (String) session.getAttribute("userid");
        String usertell = (String) session.getAttribute("usertell");
        model.addAttribute("username", username);
        model.addAttribute("userid", userid);
        model.addAttribute("usertell", usertell);
        return "index"; // index.html 파일을 반환
    }

    @PostMapping("/moveregister")
    public String moveregister() {
        return "register";
    }

    @PostMapping("/movemakecon")
    public String movemakecon(Model model, HttpSession session) {
        if (session.getAttribute("username") != null) {
            return "make_contest";
        } else {
            model.addAttribute("error", "대회를 만드실려면 로그인을 해야합니다.");
            return "login";
        }
    }

    @PostMapping("/movelogin")
    public String movelogin() {
        return "login";
    }

    @PostMapping("/movechangepassword")
    public String movechangepassword() {
        return "change_password";
    }

    @PostMapping("/home")
    public String home2(Model model, HttpSession session) {
        contestInfo(model, session);
        String username = (String) session.getAttribute("username");
        model.addAttribute("username", username);
        return "index";
    }
}