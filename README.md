# Giới thiệu

Trong mật mã học, SHA-1 là hàm băm mật mã lấy đầu vào và tạo ra giá trị băm 160 bit được gọi là thông báo đã tiêu hóa - thường được hiển thị dưới dạng số thập lục phân, dài 40 chữ số. Nó được thiết kế bởi Cơ quan An ninh Quốc gia Hoa Kỳ, và là một Tiêu chuẩn Xử lý Thông tin Liên bang Hoa Kỳ

Trong mật mã học, MD5 là một hàm băm mật mã học được sử dụng phổ biến với giá trị băm dài 128-bit. Là một chuẩn Internet, MD5 đã được dùng trong nhiều ứng dụng bảo mật, và cũng được dùng phổ biến để kiểm tra tính toàn vẹn của tập tin. Một bảng băm MD5 thường được diễn tả bằng một số hệ thập lục phân 32 ký tự

## Clone this project

```bash
git clone https://github.com/seii0000/md5-sha1-func.git
```

## Usage

```python
// Strings
          // Mã hoá văn bản bằng func SHA1
          // Nguồn nhập
          string ss1;
          cin >> ss1;

          // std::stringstream ss1("SHA of std::stringstream");
          cout << sw::sha1::calculate(ss) << endl;

// Mã hoá văn bản bằng func SHA1
          // Nguồn nhập
          string ss2;
          cin >> ss2;
          std::stringstream ss2("SHA of std::stringstream");
          cout << sw::md5::calculate(ss2) << endl;
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Nguồn tham khảo

[SHA1_MD5source_code](https://choosealicense.com/licenses/mit/](https://www.atwillys.de/content/cc/cpp-hash-algorithms-class-templates-crc-sha1-sha256-md5/)
