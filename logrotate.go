//go:build windows || linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
)

// rotateWriter 是按大小轮转的日志 Writer。
// 当写入超过 maxSize 时，将 path → path.1，path.1 → path.2，... 依次轮转，
// 超过 backupCount 的最老备份被删除。
//
// 线程安全，每个 Write 都会检查大小。
type rotateWriter struct {
	mu          sync.Mutex
	path        string
	maxSize     int64
	backupCount int
	file        *os.File
	size        int64
}

// NewRotateWriter 打开（或创建）日志文件，按大小轮转。
// maxSize <= 0 时使用 10MB 默认值；backupCount <= 0 时使用 5。
func NewRotateWriter(path string, maxSize int64, backupCount int) (*rotateWriter, error) {
	if maxSize <= 0 {
		maxSize = 10 << 20
	}
	if backupCount <= 0 {
		backupCount = 5
	}
	w := &rotateWriter{
		path:        path,
		maxSize:     maxSize,
		backupCount: backupCount,
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotateWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w.file = f
	if st, err := f.Stat(); err == nil {
		w.size = st.Size()
	} else {
		w.size = 0
	}
	return nil
}

func (w *rotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > w.maxSize {
		w.rotateLocked()
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotateLocked 调用方必须持有 w.mu
func (w *rotateWriter) rotateLocked() {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	// 从最老往新移动：path.N → path.N+1
	for i := w.backupCount - 1; i >= 1; i-- {
		oldPath := w.path + "." + strconv.Itoa(i)
		newPath := w.path + "." + strconv.Itoa(i+1)
		if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[logrotate] rename %s→%s 失败: %v\n", oldPath, newPath, err)
		}
	}
	// 删除超出 backupCount 的最老备份
	_ = os.Remove(w.path + "." + strconv.Itoa(w.backupCount+1))
	// 当前 → .1
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[logrotate] rename %s→.1 失败: %v\n", w.path, err)
	}
	// 重新打开当前文件
	if err := w.open(); err != nil {
		fmt.Fprintf(os.Stderr, "[logrotate] 重新打开 %s 失败: %v\n", w.path, err)
		w.file = nil
		w.size = 0
	}
}

// Close 关闭底层文件句柄。
func (w *rotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// String 便于调试
func (w *rotateWriter) String() string {
	return fmt.Sprintf("rotateWriter{%s, max=%d, backups=%d}", w.path, w.maxSize, w.backupCount)
}
