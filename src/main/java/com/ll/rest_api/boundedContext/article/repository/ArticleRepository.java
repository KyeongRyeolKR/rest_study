package com.ll.rest_api.boundedContext.article.repository;

import com.ll.rest_api.boundedContext.article.entity.Article;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ArticleRepository extends JpaRepository<Article, Long> {
    List<Article> findAllByOrderByIdDesc();
}