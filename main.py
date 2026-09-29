import configparser
import xml.etree.ElementTree as ET
import pandas as pd

def check_local_policy(path):
    config = configparser.ConfigParser()

    try:
        config.read(path, encoding='utf-16')
    except Exception as e:
        print(f"Ошибка чтения файла локальной политики: {e}")
        return False

    list = {
        'LockoutDuration': ('10', 'Продолжительность блокировки учетной записи'),
        'PasswordComplexity': ('1', 'Сложность пароля'),
        'MaximumPasswordAge': ('90', 'Периодичность смены пароля'),
        'MinimumPasswordAge': ('0', 'Мгновенная смена пароля'),
        'MinimumPasswordLength': ('8', 'Минимальная длина пароля'),
        'PasswordHistorySize': ('3', 'История паролей'),
        'LockoutBadCount': ('13', 'Количество неудачных попыток перед блокировкой'),
        'ResetLockoutCount': ('10', 'Сброс счётчика неудачных попыток')
    }

    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ ЛОКАЛЬНОЙ ПОЛИТИКИ")
    print("=" * 50)

    for key, (expected_value, discription) in list.items():
        actual_value = config.get('System Access', key, fallback=None)
        if actual_value is not None:
            if actual_value == expected_value:
                print(f"✅ {discription}: Соответствует ({actual_value})")
            else:
                print(f"❌ {discription}: Не соответствует ({actual_value}, ожидалось: {expected_value})")
        else:
            print(f"❌ {discription}: Настройка '{discription}' не найдена")



def check_firewall(path):
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        print(f"Ошибка чтения файла брандмауэра: {e}")
        return

    list = {
        'DisableStatefulFTP': ('dword:00000000', 'Проверка состояния для FTP включена'),
        'DisableNotifications': ('dword:00000001', 'Уведомления о событиях брандмауэра отключены'),
        'EnableFirewall': ('dword:00000001', 'Брандмауэр включен'),
        'DoNotAllowExceptions': ('dword:00000001', 'Исключения для брандмауэра не допускаются'),
        'LogDroppedPackets': ('dword:00000000', 'Ведение журнала отброшенных пакетов отключено'),
        'LogSuccessfulConnections': ('dword:00000000', 'Ведение журнала успешных подключений отключено')
    }

    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ БРАНДМАУЭРА")
    print("=" * 50)

    checked = set()

    for value in root.findall('.//Value'):
        name = value.get('Name')
        actual_value = value.get('Data', '')

        if name in list and name not in checked:
            expected_value, description = list[name]
            if actual_value is not None:
                if actual_value == expected_value:
                    print(f"✅ {description}: Соответствует ({actual_value})")
                else:
                    print(
                        f"❌ {description}: Не соответствует (найдено: {actual_value}, ожидалось: {expected_value})")
                checked.add(name)
            else:
                print(f"❌ {description}: Настройка '{name}' не найдена")


def check_av(path):
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        print(f"Ошибка чтения файла av: {e}")
        return

    list = {
        'Notification_Suppress': ('dword:00000001', 'Все уведомления антивируса отключены'),
        'ServiceKeepAlive': ('dword:00000000', 'Служба антивируса не будет перезапускаться автоматически'),
        'TamperProtection': ('dword:00000001', 'Включена защита от несанкционированного изменения настроек антивируса'),
        'RealtimeScanDirection': ('dword:00000001', 'Сканирует только входящие данные трафика'),
        'DaysUntilAggressiveCatchupQuickScan': ('dword:00000019', 'Каждые 25 дней запускается принудительный режим быстрой проверки рабочей станции'),
        'PUAProtection': ('dword:00000000', 'Защита от потенциально нежелательных программ отключена'),
        'DisableAntiSpyware': ('dword:00000000', 'Защита от шпионских программ включена'),
        'DisableAntiVirus': ('dword:00000000', 'Антивирус включен'),
        'ThreatIDDefaultAction': ('dword:00000006', 'Угроза будет удалена')
    }

    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ ЗАЩИТНИКА WINDOWS")
    print("=" * 50)

    for value in root.findall('.//Value'):
        name = value.get('Name')
        actual_value = value.get('Data', '')

        if name in list:
            expected_value, description = list[name]
            if actual_value is not None:
                if actual_value == expected_value:
                    print(f"✅ {description}: Соответствует ({actual_value})")
                else:
                    print(
                        f"❌ {description}: Не соответствует (найдено: {actual_value}, ожидалось: {expected_value})")
            else:
                print(f"❌ {description}: Настройка '{name}' не найдена")


    process_path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes"
    found_process = False

    for subkey in root.findall('.//SubKey'):
        if subkey.get('Path') == process_path:
            excluded_processes = subkey.findall('.//Value')
            for process in excluded_processes:
                if process.get('Name') == 'SecHealthUI.exe':
                    found_process = True
                    break
            break

    if found_process:
        print(f"✅ Процесс SecHealthUI.exe не будет сканироваться антивирусом")
    else:
        print(f"❌ Процесс SecHealthUI.exe будет сканироваться антивирусом")


def check_users(path):
    try:
        users_file = pd.read_csv(path, sep=';', encoding='windows-1251')
    except Exception as e:
        print(f"Ошибка чтения файла пользователей: {e}")
        return

    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ ПОЛЬЗОВАТЕЛЕЙ")
    print("=" * 50)

    standard_accounts = ['Администратор', 'Гость', 'DefaultAccount', 'WDAGUtilityAccount']

    allowed_users = ['sd.artur', 'u.juzhov', 's.makov']

    admin_users = ['sd.artur', 's.makov']

    no_password_users = ['sd.artur', 'u.juzhov', 's.makov']

    never_expire_users = ['sd.artur', 's.makov']

    for index, row in users_file.iterrows():
        user_name = row['User Name']
        account_disabled = row['Account Disabled'] == 'ИСТИНА'
        is_admin = row['Groups'] == 'Администраторы'
        password_not_required = row['Password Not Required'] == 'ИСТИНА'
        password_does_not_expire = row['Password Does Not Expire'] == 'ИСТИНА'
        auto_locked = row['Auto Locked'] == 'ИСТИНА'

        if user_name in standard_accounts:
            if account_disabled:
                print(f"✅ Стандартная учетная запись '{user_name}' отключена")
            else:
                print(f"❌ Стандартная учетная запись '{user_name}' не отключена")

        elif user_name in allowed_users:
            if user_name in admin_users:
                if is_admin:
                    print(f"✅ Пользователь '{user_name}' имеет права администратора")
                else:
                    print(f"❌ Пользователь '{user_name}' должен иметь права администратора")

            if user_name in no_password_users:
                if password_not_required:
                    print(f"✅ Пользователю '{user_name}' не требуется пароль")
                else:
                    print(f"❌ Пользователю '{user_name}' требуется пароль")

            if user_name in never_expire_users:
                if password_does_not_expire:
                    print(f"✅ Пароль пользователя '{user_name}' не имеет срока действия")
                else:
                    print(f"❌ Пароль пользователя '{user_name}' имеет срок действия")

            if auto_locked:
                print(f"✅ Учетная запись '{user_name}' не заблокирована")
            else:
                print(f"❌ Учетная запись '{user_name}' заблокирована")

        else:
            print(f"❌ Недопустимая учетная запись: {user_name}")


def check_DCAP(path):
    try:
        DCAP_file = pd.read_csv(path, sep=';', encoding='windows-1251')
    except Exception as e:
        print(f"Ошибка чтения файла пользователей: {e}")
        return

    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ ПРАВ ДОСТУПА")
    print("=" * 50)

    list = {
        ('glob.reader', r'\share\impala\Protection.dll'): ('0', '1', '0'),
        ('glob.reader', r'\share\impala\qt.conf'): ('1', '1', '0'),
        ('glob.reader', r'\share\impala\One.config'): ('1', '0', '0'),
        ('glob.reader', r'\share\impala\Update.log'): ('0', '0', '0'),
        ('glob.reader', r'\share\public\Viewer_list.resx'): ('1', '0', '1'),
        ('glob.reader', r'\share\impala\SACMonitor.exe'): ('0', '1', '0'),
        ('glob.reader', r'\share\public\Users.dat'): ('1', '0', '0'),
        ('glob.reader', r'\share\impala\tonsoft.dll'): ('0', '0', '0'),
        ('glob.reader', r'\share\public\netstandard1.3.dot'): ('0', '0', '1'),
        ('glob.reader', r'\share\public\List.resx'): ('0', '1', '0'),
        ('glob.reader', r'\share\impala\DataProtectionLabOne.deps.json'): ('1', '0', '0'),
        ('glob.reader', r'\share\public\netstandard2.0.fot'): ('1', '1', '0'),
        ('glob.reader', r'\share\impala\AntivirusMonitor.dll'): ('1', '1', '1'),
        ('glob.reader', r'\share\impala\UpdaterService.log'): ('1', '1', '1'),
        ('glob.reader', r'\share\public\netstandard1.0.dll'): ('1', '0', '1'),

        ('sd.artur', r'\share\impala\Protection.dll'): ('0', '1', '1'),
        ('sd.artur', r'\share\impala\qt.conf'): ('0', '1', '0'),
        ('sd.artur', r'\share\impala\SACMonitor.exe'): ('1', '0', '1'),
        ('sd.artur', r'\share\impala\tonsoft.dll'): ('1', '1', '0'),
        ('sd.artur', r'\share\public\List.resx'): ('0', '1', '0'),
        ('sd.artur', r'\share\public\Users.dat'): ('1', '1', '0'),
        ('sd.artur', r'\share\public\Viewer_list.resx'): ('0', '1', '0'),
        ('sd.artur', r'\share\impala\One.config'): ('1', '0', '1'),
        ('sd.artur', r'\share\impala\DataProtectionLabOne.deps.json'): ('1', '0', '1'),
        ('sd.artur', r'\share\impala\Update.log'): ('0', '1', '0'),
        ('sd.artur', r'\share\public\netstandard1.3.dot'): ('0', '0', '1'),
        ('sd.artur', r'\share\impala\UpdaterService.log'): ('0', '1', '0'),
        ('sd.artur', r'\share\public\netstandard1.0.dll'): ('1', '1', '1'),
        ('sd.artur', r'\share\impala\AntivirusMonitor.dll'): ('1', '1', '0'),
        ('sd.artur', r'\share\public\netstandard2.0.fot'): ('1', '0', '0'),

        ('u.juzhov', r'\share\impala\Protection.dll'): ('1', '1', '0'),
        ('u.juzhov', r'\share\public\netstandard1.3.dot'): ('1', '1', '1'),
        ('u.juzhov', r'\share\public\netstandard2.0.fot'): ('1', '0', '1'),
        ('u.juzhov', r'\share\public\Users.dat'): ('0', '0', '1'),
        ('u.juzhov', r'\share\impala\Update.log'): ('0', '1', '1'),
        ('u.juzhov', r'\share\impala\SACMonitor.exe'): ('1', '0', '1'),
        ('u.juzhov', r'\share\impala\UpdaterService.log'): ('0', '1', '0'),
        ('u.juzhov', r'\share\impala\AntivirusMonitor.dll'): ('0', '0', '1'),
        ('u.juzhov', r'\share\public\netstandard1.0.dll'): ('0', '1', '1'),
        ('u.juzhov', r'\share\impala\One.config'): ('1', '1', '1'),
        ('u.juzhov', r'\share\impala\qt.conf'): ('0', '0', '0'),
        ('u.juzhov', r'\share\impala\DataProtectionLabOne.deps.json'): ('1', '1', '0'),
        ('u.juzhov', r'\share\public\List.resx'): ('0', '1', '0'),
        ('u.juzhov', r'\share\public\Viewer_list.resx'): ('0', '0', '0'),
        ('u.juzhov', r'\share\impala\tonsoft.dll'): ('0', '1', '1')
    }

    for index, row in DCAP_file.iterrows():
        user_name = row['User']
        path_name = row['Path']
        read = row['Read']
        write =row['Write']
        execute = row['Execute']

        if (user_name, path_name) in list:
            expected_read, expected_write, expected_execute = list[(user_name, path_name)]

            if read == expected_read:
                if read == '1':
                    print(f"✅ Пользователь {user_name} может читать разрешённый ему файл {path_name}")
                else:
                    print(f"❌ Пользователь {user_name} может читать запрещённый ему файл {path_name}")
            else:
                if read == '1':
                    print(f"❌ Пользователь {user_name} может читать запрещённый ему файл {path_name}")
                else:
                    print(f"✅ Пользователь {user_name} может читать разрешённый ему файл {path_name}")

            if write == expected_write:
                if write == '1':
                    print(f"✅ Пользователь {user_name} может изменять разрешённый ему файл {path_name}")
                else:
                    print(f"❌ Пользователь {user_name} может изменять запрещённый ему файл {path_name}")
            else:
                if write == '1':
                    print(f"❌ Пользователь {user_name} может изменять запрещённый ему файл {path_name}")
                else:
                    print(f"✅ Пользователь {user_name} может изменять разрешённый ему файл {path_name}")

            if execute == expected_execute:
                if execute == '1':
                    print(f"✅ Пользователь {user_name} может выполнять разрешённый ему файл {path_name}")
                else:
                    print(f"❌ Пользователь {user_name} может выполнять запрещённый ему файл {path_name}")
            else:
                if execute == '1':
                    print(f"❌ Пользователь {user_name} может выполнять запрещённый ему файл {path_name}")
                else:
                    print(f"✅ Пользователь {user_name} может выполнять разрешённый ему файл {path_name}")



def checks(path):
    check_local_policy(path + 'Users/ln_swp/GP.cfg')
    check_firewall(path + 'Program Files/Windows Security/fw.xml')
    check_av(path + 'Program Files/Windows Defender/av.xml')
    check_users(path + 'Users.csv')
    check_DCAP(path + 'dcap.csv')


if __name__ == "__main__":
    base_path = 'C:/Users/Татьяна/Downloads/4var/' # Путь до папки, / в конце обязательно
    violations = []

    stations = ['ka_voyance', 'kz_cirrus', 'makh_orthrus', 'makh_ruby', 'mary_freyr',
                'od_hellion', 'od_peregrine', 'spb_hy71da', 'ula_brontes', 'vlad_pinnacle']
    for station in stations:
        print("=" * 100)
        print(" " * 40 + f"ПРОВЕРКА '{station}'")
        print("=" * 100)
        checks(base_path + station + '/')
