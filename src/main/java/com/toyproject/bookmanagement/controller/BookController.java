package com.toyproject.bookmanagement.controller;
//Controller GetMapping -> RespDto생성 -> Repository 생성 -> Mapper에 query작성 -> 
//서비스생성 -> entity에 toDto만들기(entitydhk dto는 변수가 똑같더라도 구분해서 사용)

import java.util.Map;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.toyproject.bookmanagement.dto.book.SearchBookReqDto;
import com.toyproject.bookmanagement.service.BookService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor //bookService를 IOC에서 꺼내기 위해서
public class BookController {
	
	private final BookService bookService;
	
	@GetMapping("/book/{bookId}")
	public ResponseEntity<?> getBook(@PathVariable int bookId) {
		return ResponseEntity.ok().body(bookService.getBook(bookId));
	}
	
	@GetMapping("/books")
	public ResponseEntity<?> searchBooks(SearchBookReqDto searchBookReqDto) {
		
		return ResponseEntity.ok().body(bookService.searchBooks(searchBookReqDto));
	}
	
	@GetMapping("/categories")
	public ResponseEntity<?> categories() {
		return ResponseEntity.ok(bookService.getCategories());
	}
	
	@GetMapping("/book/{bookId}/like")
	public ResponseEntity<?> getLikeCount(@PathVariable int bookId) {
		return ResponseEntity.ok().body(bookService.getLikeCount(bookId));
	}
	
   @GetMapping("/book/{bookId}/like/status")
   public ResponseEntity<?> getLikeStatus(@PathVariable int bookId, @RequestParam int userId){
      return ResponseEntity.ok().body(bookService.getLikeStatus(bookId,userId));
   }
   
   @PostMapping("/book/{bookId}/like")
   public ResponseEntity<?> setLike(@PathVariable int bookId, @RequestBody Map<String, Integer> requestMap) {
	   return ResponseEntity.ok().body(bookService.setLike(bookId, requestMap.get("userId")));
   }
   
   @DeleteMapping("/book/{bookId}/like")
   public ResponseEntity<?> disLike(@PathVariable int bookId, @RequestParam int userId) {
	   return ResponseEntity.ok().body(bookService.disLike(bookId, userId));
   }
   
   @GetMapping("/book/{bookId}/rental/list")
   public ResponseEntity<?> getRentalListByBookId(@PathVariable int bookId) {
	   return ResponseEntity.ok().body(bookService.getRentalListByBookId(bookId));
   }
   
   
   @PostMapping("/book/rental/{bookListId}")
   public ResponseEntity<?> rentalBook(@PathVariable int bookListId, @RequestBody Map<String, Integer> requestMap) {
	   return ResponseEntity.ok().body(bookService.rentalBook(bookListId, requestMap.get("userId")));
   }
   
   @DeleteMapping("/book/rental/{bookListId}")
   public ResponseEntity<?> returnBook(@PathVariable int bookListId, @RequestParam int userId) {
	   return ResponseEntity.ok().body(bookService.returnBook(bookListId, userId));
   }
   
   @PostMapping("/admin/book/list")
   public ResponseEntity<?> bookRegister(@RequestBody Map<String, Integer> requestMap) {
	   return ResponseEntity.ok().body(bookService.registeBookList(requestMap.get("bookId")));
	   
   }
	
}





