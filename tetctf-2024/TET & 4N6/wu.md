# TET & 4N6 

+ Flag 1 : Dựa theo mô tả đề bà + check history + process WINWORD.exe => có 1 file `TetCTF2024-Rules.docx` 

+ Dùng filescan để tìm offset của nó => Dump file ra => Nó thực sự ko có malicious. 

+ Dùng pstree quan sát lại các tiến trình => sau khi dùng winword nó tự phát sinh thêm ra các tiến trình khác như cmd.exe, conhost.exe, ai.exe 
+ Check cái templates của nó thì có 1 file tên `Normal.dotm` => file này đúng là chứa malicious thật. 
=> Lấy được IP và Port bằng virus total còn flag1 thì dùng olevba : ra mã base64 => decode 

+ Flag2 : cái này là do lỗi author ra đề (ko xóa flag ở history urls)  

+ Thấy nhiều process chrome.exe thì dump file database history nó ra và lụm flag2. 

+ Cách đúng thì ...


* NOTE : Rating : 74.41 => Bài này nếu nói rating 20 thì hơi nhiều.
