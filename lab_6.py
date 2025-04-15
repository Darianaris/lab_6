import hashlib
def calculate_hash(data, algorithm='sha256'):
    if algorithm == 'sha256':
        hash_object = hashlib.sha256(data.encode())
    elif algorithm == 'md5':
        hash_object = hashlib.md5(data.encode())
    else:
        raise ValueError("Unsupported algorithm")
    return hash_object.hexdigest()
# Пример использования
data = "Hello, Information Security!"
sha256_hash = calculate_hash(data, 'sha256')
md5_hash = calculate_hash(data, 'md5')
print(f"SHA-256: {sha256_hash}")
print(f"MD5: {md5_hash}")

# Проверка целостности данных
# Изменяем исходные данные
modified_data = "Hello, Information Security!!"  # Добавлено "!" в конце
sha256_hash_modified = calculate_hash(modified_data, 'sha256')
md5_hash_modified = calculate_hash(modified_data, 'md5')

print("\nПосле изменения данных:")
print(f"SHA-256 (измененные данные): {sha256_hash_modified}")
print(f"MD5 (измененные данные): {md5_hash_modified}")

# Сравнение хешей
if sha256_hash != sha256_hash_modified:
    print("SHA-256 хеши отличаются - данные изменены.")
else:
    print("SHA-256 хеши совпадают - данные целы.")

if md5_hash != md5_hash_modified:
    print("MD5 хеши отличаются - данные изменены.")
else:
    print("MD5 хеши совпадают - данные целы.")