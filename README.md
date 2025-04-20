# DDoS Defense System

Hệ thống phát hiện và phản ứng tự động với các cuộc tấn công DDoS sử dụng mô hình học máy.

---

## 1. Cài đặt hệ thống

- Tạo cấu trúc thư mục và lưu các tập tin mã nguồn vào vị trí tương ứng.
- Đảm bảo rằng tập tin mô hình `random_forest_model.pkl` từ dự án phát hiện DDoS được đặt trong thư mục `models/`.

### Cài đặt dependencies

```bash
sudo chmod +x install_dependencies.sh
sudo ./install_dependencies.sh
```

### Cài đặt dịch vụ hệ thống

```bash
sudo chmod +x setup_service.sh
sudo ./setup_service.sh
```

### 2. Kiểm tra trạng thái dịch vụ

```bash
sudo systemctl status ddos-defense
```

### 3. Xem nhật ký hệ thống

```bash
sudo journalctl -u ddos-defense
```

### 4. Điều khiển dịch vụ:
- Khởi động: sudo systemctl start ddos-defense
- Dừng: sudo systemctl stop ddos-defense
- Khởi động lại: sudo systemctl restart ddos-defense
### 5. Sử dụng API:
- Bạn có thể tương tác với hệ thống thông qua API:

- Xem trạng thái: curl http://127.0.0.1:5000/api/status
- Xem danh sách IP bị chặn: curl http://127.0.0.1:5000/api/blocked
- Bỏ chặn IP: curl -X POST http://127.0.0.1:5000/api/unblock/1.2.3.4
- Chặn IP thủ công: curl -X POST http://127.0.0.1:5000/api/block/1.2.3.4

### 6. Chạy giao diện Web (tùy chọn):
```bash
pip3 install streamlit
streamlit run web_ui.py
```
