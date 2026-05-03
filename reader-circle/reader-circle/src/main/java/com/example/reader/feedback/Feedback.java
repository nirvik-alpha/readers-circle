package com.example.reader.feedback;

import com.example.reader.book.Book;
import com.example.reader.common.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder // can handle parent-child class; normal builder cant support inheritance properly
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Feedback extends BaseEntity {


    private Double note;  // 1-5 stars

    private String comment;

    @ManyToOne
    @JoinColumn(name = "book_id")
    private Book book;

}
