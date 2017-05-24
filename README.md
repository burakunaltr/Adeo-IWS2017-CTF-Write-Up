# Adeo-IWS2017-CTF-Write-Up
Adeo Security 2017 stajer alımı için yapılan CTF cevapları.


# Web200

http://ctf_sorular.adeosecurity.com/Soru3/

Sitenin headerına bakmak yeterli.

Flag = HTTPHeaderDiyeBirseyVar

                    

# Web500         

http://ctf_sorular.adeosecurity.com/Soru4/

Sitede öğeyi incele diyince bi js dosyası çağırıldığı görülüyor.
JS dosyasını inceleyince içinde hex kodları dikkat çekiyor.
Hex kodlarını çevirdikçe sonuç çıkıyor..

Flag = HTML5IleCokDegisiklikOldu

                    

# Misc400         

http://ctf.adeosecurity.com/system/question_files/files/000/000/003/original/logo.zip?1494617211

Soruda zip dosyası içinden bir resim çıkıyor.
Resmi binwalk a verince içinde zip olduğunu söylüyor.
Binwalk ile zip dosyasını çıkarıyoruz. Zip password soruyor.
Soruda verilen metin Sun-Tzu dan alıntı. password "suntzu".
Zip içinden çıkan config.php dosyasında flag bilgisi yer alıyor.


Flag = 1337_h4x0r

                    

# Misc750         

http://ctf.adeosecurity.com/system/question_files/files/000/000/008/original/soundtrack.zip?1494621211

Soruda zip dosyası içinden bir ses dosyası çıkıyor.
Güzel melodi ancak ters giden bi şeyler var :) 
Sesi AVS Audio Editor ile ters çevirdim ve shazamladım.


Flag = The Godfather

                    
# Crypto600         

http://ctf.adeosecurity.com/system/question_files/files/000/000/005/original/data.zip?1494617320

Sorudaki zip dosyasının içinden data adında bir dosya çıkıyor.
Dosyanın içinde bir sürü karışık harfler var.
Alphabetical subsition olsa gerek :)
Subsition solver araçlarından birine vererek flagi bulabilirdik.
https://www.guballa.de/substitution-solver


Flag = dwqkojmzcnvbruypx

                     


# System-Network300         

http://ctf.adeosecurity.com/system/question_files/files/000/000/011/original/malformed.zip?1494631902

Soruda verilen pcap dosyasında Malformed paketlerinin incelenmesi gerekiyordu.
filtre alanına _ws.malformed girildiğinde flag çıkan paketlerden herhangi birinin hex dökümünde yer alıyordu.


Flag = StopWarHugMore

                         

# System-Network600         

http://ctf.adeosecurity.com/system/question_files/files/000/000/004/original/flag.zip?1494617275

Soruda verilen zip dosyasından bir adet lsass.DMP dosyası çıkıyordu.
lsass gördüğüm zaman direk mimikatz aracı gelir aklıma.
Mimikatze verdim logonPasswords altında kullanıcıların Passwordleri null dönüyordu.
NTLM karşısındaki veriyi NTLM decrypter ile çözünce flag karşımdaydı.


Flag = Password1

                         

# System-Network1000         

http://ctf.adeosecurity.com/system/question_files/files/000/000/006/original/Kirbi.zip?1494618113

Mimikatz aracını githubda incelerken kirbi ve kerberos diye bi şeyler gördüm.

kerberos::ptt flag.kirbi
kerberos::list

yapınca Client name düşüyor. Ancak sonradan farkettim ki linuxta strings ile de gözüküyor bu veri :)


Flag = 20171012051217

                          

# Reverse700-2         

http://ctf.adeosecurity.com/system/question_files/files/000/000/002/original/Form.zip?1494616294

Verilen zip dosyasından Form.exe adında çalıştırılabilir bir dosya çıkıyor.
Çalıştırdığımızda bizden username password bilgisi istiyor ama soru reverse sorusu :) Geçiyoruz.
Bazen desktop toollarla işimiz olsa da bu soru için online toollar iş yapıyor.
https://retdec.com/decompilation-run/
exeyi bu toola verince .dsm çıktısı veriyor. İçinde flag diye search ettiğimizde flag karşımızda.

Flag = flag{rundll32.dll}

                       

# Reverse700-1         

http://ctf.adeosecurity.com/system/question_files/files/000/000/001/original/shellcode.zip?1494616005

Verilen zip dosyasından .dat uzantılı bir dosya çıkıyor. Allah'ın emri üzerine notepadde açtım.
Hex kodları karşıladı beni. hex to text araçlarına verdim dönen sonuç kısmen tatmin ediciydi.
Tebrikler ve shellcode tarzı şeyler okuyabiliyordum. Hex to exe, hex to assembly tarzı bi çok dönüştürme yaptım.
Saatler sonra başlık aracılığıyla shellcode to exe yaptım ve flag ekrana basıldı :)

Flag = flag{sh3llcode4ever}

                       

# Web1000         

http://ctf_sorular.adeosecurity.com/Soru2/

Verilen adreste bir sqli zaafiyeti olduğu bildiriliyor. Önce masum bir arama yapıyoruz.
Datanın POST methoduyla gittiğini anladıktan sonra giden veriyi görebilmek için
burpsuite aracını kullanıyoruz. Firefoxta local proxymizi ayarladıktan sonra
siteye bir sorgu atıyoruz ve burp e datanın düşmesini sağlıyoruz. Bundan sonrası sqlmap in işi..
Sqlmapte 

sqlmap -u "URL" --data="POST edilecek veri yani csrf=..........&search=........" --dbs

veritabanını bulduktan sonra 

sqlmap -u "URL" --data="POST Verisi" -D DatabaseADI --tables

yaptıktan sonra flag ben burdayım diye bağırıyor :)

Flag = flag(SQLi_mi_Oda_Ne)

                     

# Reverse1000         

http://ctf.adeosecurity.com/system/question_files/files/000/000/009/original/ParolayiBul.zip?1494622774

Verilen zip dosyasının içinde bir exe bekliyor bizi. Parametre olarak password bilgisi istiyor.
Herhangi bir ip ucu olmadığı için decompile etmeye başlayabiliriz. IDA Pro adlı decompile aracıyla exemizi
assemblye çeviriyoruz. burada dikkat edilmesi gereken bi şey var. Hafızasındaki string ile bizden almak
istediği stringi karşılaştırıyor. Tam buraya (call    esi ; __vbaStrCopy) bir breakpoint koyarak kodu debug ediyoruz.
IDA Pro üzerinde General Register kısmında yazanlara göz atıyoruz. flag kelimesini yakaladık. oraya jump edip
flagi okuyoruz.

Flag = flag(nobody)

                      

# Web1500         

http://ctf_sorular.adeosecurity.com/Soru1/

Sitede bir form vardı ve bizden xss açıklığı kullanarak flagi bulmamız isteniyordu.
xsshunter adlı websiteyi kullanarak herhangi bir payloadı mesaj kısmında yedirmemiz yetiyordu.
xsshuntera gelen bağlantıda flag gözüküyordu.

Flag = flag(XSS_Tehlikelidir)

                      

