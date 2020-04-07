package spring.security.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1001,"Virat Kohli"),
            new Student(1002,"MS Dhoni"),
            new Student(1003,"Rohit Sharma"),
            new Student(1004,"Suresh Raina"),
            new Student(1005,"De Kock")
    );
    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return STUDENTS.stream()
                .filter(s -> studentId.equals(s.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Student "+studentId+"  does not exist"));

    }
}
