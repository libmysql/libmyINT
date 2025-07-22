#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import requests
import json
import socket
import whois
import dns.resolver
import phonenumbers
import re
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style, init

# Инициализация colorama
init(autoreset=True)

# Константы
VERSION = "2.0"
AUTHOR = "Anonymous Researcher"
GITHUB = "https://github.com/yourusername/libmyINT"
BANNER = f"""
{Fore.RED} _     _ _     _       ___ _____ _____ 
{Fore.RED}| |   (_) |   | |     |_  |_   _|_   _|
{Fore.RED}| |    _| |__ | |__     | | | |   | |  
{Fore.RED}| |   | | '_ \| '_ \    | | | |   | |  
{Fore.RED}| |___| | |_) | | | |/\__/ /_| |_ _| |_ 
{Fore.RED}\_____/_|_.__/|_| |_|\____/ \___/ \___/ 
{Fore.YELLOW}Version: {VERSION} | By: {AUTHOR}
{Fore.CYAN}GitHub: {GITHUB}
{Style.RESET_ALL}
"""

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_slow(text):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.03)
    print()

def show_loading(seconds=2):
    for i in range(seconds*10):
        sys.stdout.write(f"\r{Fore.YELLOW}Загрузка{'...'[:i%3+1]}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.1)
    print()

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def main_menu():
    clear_screen()
    print(BANNER)
    print(f"{Fore.GREEN}Основное меню:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Поиск информации по IP")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Анализ домена")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Анализ номера телефона")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Анализ email")
    print(f"{Fore.YELLOW}5.{Style.RESET_ALL} Поиск по имени пользователя")
    print(f"{Fore.YELLOW}6.{Style.RESET_ALL} Проверка утечек данных")
    print(f"{Fore.YELLOW}7.{Style.RESET_ALL} Дополнительные инструменты")
    print(f"{Fore.YELLOW}8.{Style.RESET_ALL} Выход")
    
    choice = input(f"\n{Fore.CYAN}Выберите опцию (1-8): {Style.RESET_ALL}")
    return choice

def ip_lookup():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Поиск информации по IP ▓▓▓{Style.RESET_ALL}\n")
    ip = input(f"{Fore.CYAN}Введите IP-адрес: {Style.RESET_ALL}")
    
    if not validate_ip(ip):
        print(f"{Fore.RED}Ошибка: Неверный формат IP-адреса{Style.RESET_ALL}")
        input(f"\n{Fore.CYAN}Нажмите Enter для продолжения...{Style.RESET_ALL}")
        return
    
    show_loading()
    
    try:
        # Использование ip-api.com
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719")
        data = response.json()
        
        if data['status'] == 'success':
            print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
            print(f"║        ОСНОВНАЯ ИНФОРМАЦИЯ       ║")
            print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
            print(f"🌍 Страна: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
            print(f"🏙️ Регион: {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
            print(f"🏡 Город: {data.get('city', 'N/A')}")
            print(f"📮 Почтовый индекс: {data.get('zip', 'N/A')}")
            print(f"🕒 Часовой пояс: {data.get('timezone', 'N/A')}")
            print(f"📍 Координаты: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            
            print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
            print(f"║        СЕТЕВАЯ ИНФОРМАЦИЯ       ║")
            print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
            print(f"📡 Провайдер: {data.get('isp', 'N/A')}")
            print(f"🏢 Организация: {data.get('org', 'N/A')}")
            print(f"🔢 AS номер: {data.get('as', 'N/A')}")
            print(f"🏷️ AS имя: {data.get('asname', 'N/A')}")
            print(f"🔁 Обратный DNS: {data.get('reverse', 'N/A')}")
            
            print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
            print(f"║     ТЕХНИЧЕСКАЯ ИНФОРМАЦИЯ     ║")
            print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
            print(f"📱 Мобильное: {'✅ Да' if data.get('mobile', False) else '❌ Нет'}")
            print(f"🔒 Прокси/VPN: {'✅ Да' if data.get('proxy', False) else '❌ Нет'}")
            print(f"🖥️ Хостинг: {'✅ Да' if data.get('hosting', False) else '❌ Нет'}")
            
            # Дополнительные проверки
            print(f"\n{Fore.YELLOW}[*] Проверка открытых портов...{Style.RESET_ALL}")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            if open_ports:
                print(f"{Fore.RED}Открытые порты: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}Нет открытых портов из списка распространенных{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Ошибка: {data.get('message', 'Неизвестная ошибка')}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def domain_lookup():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Анализ домена ▓▓▓{Style.RESET_ALL}\n")
    domain = input(f"{Fore.CYAN}Введите доменное имя (например: example.com): {Style.RESET_ALL}")
    
    show_loading()
    
    try:
        print(f"\n{Fore.YELLOW}[*] Запрос WHOIS информации...{Style.RESET_ALL}")
        domain_info = whois.whois(domain)
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║   РЕГИСТРАЦИОННАЯ ИНФОРМАЦИЯ   ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"🔗 Домен: {domain_info.domain_name}")
        print(f"🏢 Регистратор: {domain_info.registrar}")
        print(f"📅 Дата создания: {domain_info.creation_date}")
        print(f"⏳ Дата истечения: {domain_info.expiration_date}")
        print(f"🔄 Дата обновления: {domain_info.updated_date}")
        print(f"📊 Статус: {', '.join(domain_info.status) if domain_info.status else 'N/A'}")
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║     КОНТАКТНАЯ ИНФОРМАЦИЯ      ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"👤 Владелец: {domain_info.name}")
        print(f"🏛️ Организация: {domain_info.org}")
        print(f"🏠 Адрес: {domain_info.address}")
        print(f"🌆 Город: {domain_info.city}")
        print(f"🌍 Страна: {domain_info.country}")
        
        print(f"\n{Fore.YELLOW}[*] Запрос DNS информации...{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║          DNS ЗАПИСИ          ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        
        # A записи
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            print("🅰️ A записи:")
            for a in a_records:
                print(f" - {a.address}")
        except:
            print("❌ A записи: не найдены")
            
        # MX записи
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print("\n📧 MX записи:")
            for mx in mx_records:
                print(f" - {mx.exchange} (приоритет {mx.preference})")
        except:
            print("\n❌ MX записи: не найдены")
            
        # NS записи
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            print("\n🔗 NS записи:")
            for ns in ns_records:
                print(f" - {ns.target}")
        except:
            print("\n❌ NS записи: не найдены")
            
        # TXT записи
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            print("\n📝 TXT записи:")
            for txt in txt_records:
                print(f" - {' '.join(txt.strings)}")
        except:
            print("\n❌ TXT записи: не найдены")
            
        # Проверка SSL
        print(f"\n{Fore.YELLOW}[*] Проверка SSL сертификата...{Style.RESET_ALL}")
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    print(f"\n{Fore.GREEN}✅ SSL сертификат найден{Style.RESET_ALL}")
                    print(f"📜 Организация: {cert.get('organizationName', 'N/A')}")
                    print(f"⏳ Действителен до: {cert.get('notAfter', 'N/A')}")
        except:
            print(f"\n{Fore.RED}❌ SSL сертификат не найден или ошибка проверки{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def phone_lookup():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Анализ номера телефона ▓▓▓{Style.RESET_ALL}\n")
    phone = input(f"{Fore.CYAN}Введите номер телефона (с кодом страны, например +79123456789): {Style.RESET_ALL}")
    
    show_loading()
    
    try:
        # Парсинг номера
        parsed_number = phonenumbers.parse(phone)
        
        if not phonenumbers.is_valid_number(parsed_number):
            print(f"{Fore.RED}❌ Ошибка: Номер недействителен{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Нажмите Enter для продолжения...{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║     ОСНОВНАЯ ИНФОРМАЦИЯ      ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"📱 Международный формат: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"🔢 E.164 формат: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)}")
        print(f"🏠 Национальный формат: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)}")
        
        # Информация о операторе
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║     ИНФОРМАЦИЯ ОБ ОПЕРАТОРЕ    ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        try:
            operator = carrier.name_for_number(parsed_number, "ru")
            print(f"📶 Оператор: {operator if operator else 'Неизвестно'}")
        except:
            print("❌ Оператор: Информация недоступна")
        
        # Геолокация
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║          ГЕОЛОКАЦИЯ          ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        try:
            region = geocoder.description_for_number(parsed_number, "ru")
            print(f"🌍 Регион: {region if region else 'Неизвестно'}")
        except:
            print("❌ Регион: Информация недоступна")
        
        # Часовой пояс
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║        ЧАСОВОЙ ПОЯС         ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        try:
            tz = timezone.time_zones_for_number(parsed_number)
            print(f"🕒 Часовой пояс: {tz[0] if tz else 'Неизвестно'}")
        except:
            print("❌ Часовой пояс: Информация недоступна")
            
        # Дополнительные проверки
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║   ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ  ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"🔍 Тип номера: {phonenumbers.number_type(parsed_number)}")
        print(f"❓ Возможный номер: {'✅ Да' if phonenumbers.is_possible_number(parsed_number) else '❌ Нет'}")
        print(f"✔️ Действительный номер: {'✅ Да' if phonenumbers.is_valid_number(parsed_number) else '❌ Нет'}")
        
        # Проверка в социальных сетях
        print(f"\n{Fore.YELLOW}[*] Проверка в социальных сетях...{Style.RESET_ALL}")
        national_number = str(parsed_number.national_number)
        country_code = str(parsed_number.country_code)
        
        # Форматы номеров для проверки
        phone_formats = [
            f"{country_code}{national_number}",
            f"+{country_code}{national_number}",
            national_number
        ]
        
        found = False
        for fmt in phone_formats:
            url = f"https://www.facebook.com/search/top/?q={fmt}"
            try:
                response = requests.get(url, timeout=5)
                if "По вашему запросу ничего не найдено" not in response.text:
                    print(f"{Fore.GREEN}🔍 Возможный профиль Facebook: {url}{Style.RESET_ALL}")
                    found = True
            except:
                pass
                
        if not found:
            print(f"{Fore.RED}❌ Профили в социальных сетях не найдены{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def email_lookup():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Анализ email ▓▓▓{Style.RESET_ALL}\n")
    email = input(f"{Fore.CYAN}Введите email адрес: {Style.RESET_ALL}")
    
    if not validate_email(email):
        print(f"{Fore.RED}❌ Ошибка: Неверный формат email{Style.RESET_ALL}")
        input(f"\n{Fore.CYAN}Нажмите Enter для продолжения...{Style.RESET_ALL}")
        return
    
    show_loading()
    
    try:
        domain = email.split('@')[-1]
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║     ОСНОВНАЯ ИНФОРМАЦИЯ      ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"📧 Email: {email}")
        print(f"🌐 Домен: {domain}")
        
        # Проверка MX записей
        print(f"\n{Fore.YELLOW}[*] Проверка MX записей домена...{Style.RESET_ALL}")
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(f"{Fore.GREEN}✅ MX записи найдены:{Style.RESET_ALL}")
            for mx in mx_records:
                print(f" - {mx.exchange} (приоритет {mx.preference})")
        except:
            print(f"{Fore.RED}❌ MX записи не найдены - домен может не существовать{Style.RESET_ALL}")
        
        # Проверка через MailboxValidator (бесплатный вариант)
        print(f"\n{Fore.YELLOW}[*] Проверка валидности email...{Style.RESET_ALL}")
        try:
            response = requests.get(f"https://api.mailboxvalidator.com/v1/validation/single?email={email}&key=free")
            data = response.json()
            
            if data.get('status') == 'True':
                print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
                print(f"║     РЕЗУЛЬТАТЫ ПРОВЕРКИ     ║")
                print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
                print(f"✔️ Действительный email: {'✅ Да' if data.get('is_verified') == 'True' else '❌ Нет'}")
                print(f"🌐 Домен: {data.get('domain', 'N/A')}")
                print(f"📧 Почтовый сервер: {data.get('mail_server', 'N/A')}")
                print(f"🔌 SMTP проверка: {'✅ Да' if data.get('smtp_connect') == 'True' else '❌ Нет'}")
                print(f"📝 Валидный синтаксис: {'✅ Да' if data.get('is_valid_syntax') == 'True' else '❌ Нет'}")
                print(f"🏠 Домен существует: {'✅ Да' if data.get('is_domain') == 'True' else '❌ Нет'}")
            else:
                print(f"{Fore.RED}❌ Ошибка проверки: {data.get('error_message', 'Неизвестная ошибка')}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Ошибка API: {str(e)}{Style.RESET_ALL}")
        
        # Проверка в социальных сетях
        print(f"\n{Fore.YELLOW}[*] Проверка в социальных сетях...{Style.RESET_ALL}")
        social_networks = {
            "Facebook": f"https://www.facebook.com/{email}",
            "Twitter": f"https://twitter.com/{email}",
            "Instagram": f"https://instagram.com/{email}",
            "LinkedIn": f"https://www.linkedin.com/in/{email}"
        }
        
        found = False
        for name, url in social_networks.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}🔍 {name}: {url}{Style.RESET_ALL}")
                    found = True
            except:
                pass
                
        if not found:
            print(f"{Fore.RED}❌ Профили в социальных сетях не найдены{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def username_lookup():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Поиск по имени пользователя ▓▓▓{Style.RESET_ALL}\n")
    username = input(f"{Fore.CYAN}Введите имя пользователя: {Style.RESET_ALL}")
    
    show_loading()
    
    try:
        print(f"\n{Fore.YELLOW}[*] Поиск по социальным сетям...{Style.RESET_ALL}")
        
        # Расширенный список социальных сетей
        social_networks = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Facebook": f"https://facebook.com/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Telegram": f"https://t.me/{username}",
            "VK": f"https://vk.com/{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}",
            "Medium": f"https://medium.com/@{username}",
            "Steam": f"https://steamcommunity.com/id/{username}",
            "Flickr": f"https://flickr.com/people/{username}",
            "SoundCloud": f"https://soundcloud.com/{username}",
            "DeviantArt": f"https://{username}.deviantart.com",
            "Vimeo": f"https://vimeo.com/{username}",
            "Wikipedia": f"https://en.wikipedia.org/wiki/User:{username}",
            "Keybase": f"https://keybase.io/{username}",
            "HackerNews": f"https://news.ycombinator.com/user?id={username}"
        }
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║       РЕЗУЛЬТАТЫ ПОИСКА      ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        
        found = False
        for name, url in social_networks.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}✅ {name}: {url}{Style.RESET_ALL}")
                    found = True
                else:
                    print(f"{Fore.RED}❌ {name}: Не найдено{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}❌ {name}: Ошибка проверки{Style.RESET_ALL}")
                
        if not found:
            print(f"\n{Fore.RED}❌ Профили не найдены ни в одной из проверенных социальных сетей{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def check_leaks():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Проверка утечек данных ▓▓▓{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Проверка по email")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Проверка по имени пользователя")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Проверка по номеру телефона")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Назад в меню")
    
    choice = input(f"\n{Fore.CYAN}Выберите опцию (1-4): {Style.RESET_ALL}")
    
    if choice == '4':
        return
    
    query = input(f"\n{Fore.CYAN}Введите данные для проверки: {Style.RESET_ALL}")
    
    show_loading(3)
    
    try:
        print(f"\n{Fore.YELLOW}[*] Проверка через Scylla.sh API...{Style.RESET_ALL}")
        
        # Использование Scylla.sh (открытая база утечек)
        response = requests.get(f"https://scylla.sh/search?q={query}", headers={'User-Agent': 'libmyINT OSINT Tool'})
        
        if response.status_code == 200:
            data = response.json()
            
            if len(data) > 0:
                print(f"\n{Fore.RED}╔════════════════════════════════╗")
                print(f"║      ОБНАРУЖЕНЫ УТЕЧКИ      ║")
                print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
                for leak in data[:5]:  # Ограничим вывод 5 утечками
                    print(f"\n{Fore.YELLOW}📌 Источник: {leak.get('fields', {}).get('domain', 'N/A')}{Style.RESET_ALL}")
                    print(f"📅 Дата утечки: {leak.get('_source', {}).get('seen_date', 'N/A')}")
                    print(f"📊 Тип данных: {leak.get('_source', {}).get('data_type', 'N/A')}")
                    
                    # Выводим все доступные поля
                    print(f"\n{Fore.CYAN}📋 Доступные данные:{Style.RESET_ALL}")
                    fields = leak.get('fields', {})
                    for key in ['email', 'username', 'password', 'phone', 'name', 'ip']:
                        if key in fields and fields[key]:
                            print(f"{key}: {fields[key]}")
            else:
                print(f"\n{Fore.GREEN}✅ Данные не найдены в известных утечках{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Ошибка API: {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def additional_tools():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Дополнительные инструменты ▓▓▓{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Генератор фальшивых данных")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Проверка пароля на утечки")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Назад в меню")
    
    choice = input(f"\n{Fore.CYAN}Выберите опцию (1-3): {Style.RESET_ALL}")
    
    if choice == '1':
        fake_data_generator()
    elif choice == '2':
        password_check()
    elif choice == '3':
        return

def fake_data_generator():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Генератор фальшивых данных ▓▓▓{Style.RESET_ALL}\n")
    
    try:
        response = requests.get("https://randomuser.me/api/")
        data = response.json()['results'][0]
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║        ЛИЧНЫЕ ДАННЫЕ        ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"👤 Имя: {data['name']['first']} {data['name']['last']}")
        print(f"📧 Email: {data['email']}")
        print(f"📱 Телефон: {data['phone']}")
        print(f"🏠 Адрес: {data['location']['street']['number']} {data['location']['street']['name']}")
        print(f"🌆 Город: {data['location']['city']}")
        print(f"🌍 Страна: {data['location']['country']}")
        print(f"📮 Почтовый индекс: {data['location']['postcode']}")
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║        УЧЕТНЫЕ ДАННЫЕ       ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"👤 Логин: {data['login']['username']}")
        print(f"🔑 Пароль: {data['login']['password']}")
        
        print(f"\n{Fore.GREEN}╔════════════════════════════════╗")
        print(f"║        ДРУГАЯ ИНФОРМАЦИЯ    ║")
        print(f"╚════════════════════════════════╝{Style.RESET_ALL}")
        print(f"🎂 Дата рождения: {data['dob']['date'][:10]}")
        print(f"🆔 ID: {data['id']['value']}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def password_check():
    clear_screen()
    print(f"{Fore.GREEN}▓▓▓ Проверка пароля на утечки ▓▓▓{Style.RESET_ALL}\n")
    print(f"{Fore.RED}ВНИМАНИЕ: Не используйте реальные пароли!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Эта проверка использует только первые 5 символов хеша.{Style.RESET_ALL}\n")
    
    password = input(f"{Fore.CYAN}Введите пароль для проверки: {Style.RESET_ALL}")
    
    show_loading()
    
    try:
        import hashlib
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        
        print(f"\n{Fore.YELLOW}[*] Проверка через Have I Been Pwned API...{Style.RESET_ALL}")
        response = requests.get(f"https://api.pwnedpasswords.com/range/{hash_prefix}")
        
        if response.status_code == 200:
            found = False
            for line in response.text.splitlines():
                suffix, count = line.split(':')
                if (hash_prefix + suffix) == sha1_hash:
                    print(f"\n{Fore.RED}❌ Пароль найден в {count} утечках!{Style.RESET_ALL}")
                    print(f"🔒 Хеш: {sha1_hash}")
                    found = True
                    break
                    
            if not found:
                print(f"\n{Fore.GREEN}✅ Пароль не найден в известных утечках{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Ошибка API: {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {str(e)}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Нажмите Enter для возврата в меню...{Style.RESET_ALL}")

def main():
    while True:
        choice = main_menu()
        
        if choice == '1':
            ip_lookup()
        elif choice == '2':
            domain_lookup()
        elif choice == '3':
            phone_lookup()
        elif choice == '4':
            email_lookup()
        elif choice == '5':
            username_lookup()
        elif choice == '6':
            check_leaks()
        elif choice == '7':
            additional_tools()
        elif choice == '8':
            clear_screen()
            print_slow(f"{Fore.GREEN}Спасибо за использование libmyINT!{Style.RESET_ALL}")
            print_slow(f"{Fore.YELLOW}Выход...{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}❌ Неверный выбор. Пожалуйста, выберите от 1 до 8.{Style.RESET_ALL}")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}❌ Программа прервана пользователем.{Style.RESET_ALL}")
        sys.exit(0)
