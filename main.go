package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/argon2"
)

const (
	bufferSize = 4 * 1024 * 1024  // Increased buffer size for I/O operations
	chunkSize  = 32 * 1024 * 1024 // chunkSize is the chunk size for large files during encryption/decryption
)

// CompressionAlgorithm represents the available compression algorithms.
type CompressionAlgorithm string

const (
	GzipAlgo   CompressionAlgorithm = "gzip"
	ZstdAlgo   CompressionAlgorithm = "zstd"
	LZ4Algo    CompressionAlgorithm = "lz4"
	S2Algo     CompressionAlgorithm = "s2"
	NoCompress CompressionAlgorithm = "none"
)

// ArchiveFormat represents the available archive formats.
type ArchiveFormat string

const (
	ZipFormat    ArchiveFormat = "zip"
	TarGzFormat  ArchiveFormat = "tar.gz"
	TarXzFormat  ArchiveFormat = "tar.xz"
	SevenZFormat ArchiveFormat = "7z" // Placeholder, requires external library integration
)

// OperationMode represents the program's operating mode.
type OperationMode string

const (
	CompressMode   OperationMode = "compress"
	DecompressMode OperationMode = "decompress"
	ArchiveMode    OperationMode = "archive"
	ExtractMode    OperationMode = "extract"
)

// ChecksumAlgorithm represents available checksum algorithms.
type ChecksumAlgorithm string

const (
	MD5Checksum   ChecksumAlgorithm = "md5"
	CRC32Checksum ChecksumAlgorithm = "crc32"
)

type Config struct {
	Mode          OperationMode
	Algorithm     CompressionAlgorithm
	ArchiveFormat ArchiveFormat
	Input         []string
	Output        string
	Password      string
	ChecksumAlgo  ChecksumAlgorithm
	CompressDir   bool
	NumRoutines   int
	ZstdLevel     int
	Argon2Memory  uint32
	Argon2Time    uint32
	Argon2Threads uint8
}

func main() {
	a := app.New()
	w := a.NewWindow("Go Archiver and Compressor")
	w.Resize(fyne.NewSize(700, 500))

	logWriter := newFyneLogWriter(w)
	log.SetOutput(logWriter) // Redirect log output to a GUI widget

	mode, algo, archiveFormat, checksumAlgo := initModeAndAlgoControls()
	inputEntry, outputEntry, passwordEntry, openFilesButton, openOutputButton := initFileControls(w)
	compressDirCheck := initCompressDirCheck()
	numRoutinesEntry := initNumRoutinesEntry()
	zstdLevelEntry, argon2MemoryEntry, argon2TimeEntry, argon2ThreadsEntry := initAdvancedSettings()
	var progressBar *widget.ProgressBar
	outputArea := widget.NewEntry()
	outputArea.MultiLine = true
	outputArea.Disable()
	visualCue := widget.NewLabel("")
	startButton := widget.NewButton("Start", nil) // Initialize with nil function

	var inputFilePaths []string

	openFilesButton.OnTapped = func() {
		handleInputFileSelection(w, mode, compressDirCheck, inputEntry, &inputFilePaths)
	}

	openOutputButton.OnTapped = func() {
		handleOutputFileSelection(w, mode, inputFilePaths, outputEntry)
	}

	startButton.OnTapped = func() {
		handleStartAction(w, mode, algo, archiveFormat, checksumAlgo, inputFilePaths, inputEntry, outputEntry, passwordEntry, compressDirCheck, numRoutinesEntry, zstdLevelEntry, argon2MemoryEntry, argon2TimeEntry, argon2ThreadsEntry, visualCue, &progressBar, outputArea, logWriter)
	}

	mode.OnChanged = func(s string) {
		updateUIOnModeChange(s, compressDirCheck, archiveFormat, openFilesButton, openOutputButton)
	}

	compressDirCheck.OnChanged = func(b bool) {
		updateOpenFileButtonText(mode, compressDirCheck, openFilesButton)
	}

	configForm := createConfigForm(mode, algo, archiveFormat, checksumAlgo, inputEntry, openFilesButton, outputEntry, openOutputButton, passwordEntry, compressDirCheck, numRoutinesEntry, zstdLevelEntry, argon2MemoryEntry, argon2TimeEntry, argon2ThreadsEntry)
	controls := container.NewVBox(startButton, visualCue)
	content := container.NewBorder(configForm, controls, nil, nil, outputArea)

	if _, ok := fyne.CurrentApp().Driver().(desktop.Driver); ok {
		m := createMainMenu(a, w)
		w.SetMainMenu(m)
	}

	w.SetContent(content)
	w.ShowAndRun()
}

func initModeAndAlgoControls() (*widget.RadioGroup, *widget.Select, *widget.Select, *widget.Select) {
	mode := widget.NewRadioGroup([]string{string(CompressMode), string(DecompressMode), string(ArchiveMode), string(ExtractMode)}, nil)
	algo := widget.NewSelect([]string{string(GzipAlgo), string(ZstdAlgo), string(LZ4Algo), string(S2Algo), string(NoCompress)}, nil)
	algo.SetSelected(string(GzipAlgo))
	archiveFormat := widget.NewSelect([]string{string(ZipFormat), string(TarGzFormat), string(TarXzFormat), string(SevenZFormat)}, nil)
	archiveFormat.SetSelected(string(ZipFormat))
	checksumAlgo := widget.NewSelect([]string{string(MD5Checksum), string(CRC32Checksum)}, nil)
	checksumAlgo.SetSelected(string(MD5Checksum))
	return mode, algo, archiveFormat, checksumAlgo
}

func initFileControls(w fyne.Window) (*widget.Entry, *widget.Entry, *widget.Entry, *widget.Button, *widget.Button) {
	inputEntry := widget.NewEntry()
	outputEntry := widget.NewEntry()
	passwordEntry := widget.NewEntry()
	passwordEntry.Password = true
	openFilesButton := widget.NewButton("Select Input File(s)", nil)
	openOutputButton := widget.NewButton("Select Output Path", nil)
	return inputEntry, outputEntry, passwordEntry, openFilesButton, openOutputButton
}

func initCompressDirCheck() *widget.Check {
	return widget.NewCheck("Compress Directory", nil)
}

func initNumRoutinesEntry() *widget.Entry {
	numRoutinesEntry := widget.NewEntry()
	numRoutinesEntry.SetText(fmt.Sprintf("%d", runtime.NumCPU()))
	return numRoutinesEntry
}

func initAdvancedSettings() (*widget.Entry, *widget.Entry, *widget.Entry, *widget.Entry) {
	zstdLevelEntry := widget.NewEntry()
	zstdLevelEntry.SetPlaceHolder("Default")
	argon2MemoryEntry := widget.NewEntry()
	argon2MemoryEntry.SetPlaceHolder("64")
	argon2TimeEntry := widget.NewEntry()
	argon2TimeEntry.SetPlaceHolder("1")
	argon2ThreadsEntry := widget.NewEntry()
	argon2ThreadsEntry.SetPlaceHolder(fmt.Sprintf("%d", runtime.NumCPU()))
	return zstdLevelEntry, argon2MemoryEntry, argon2TimeEntry, argon2ThreadsEntry
}

func handleInputFileSelection(w fyne.Window, mode *widget.RadioGroup, compressDirCheck *widget.Check, inputEntry *widget.Entry, inputFilePaths *[]string) {
	if mode.Selected == string(DecompressMode) || mode.Selected == string(CompressMode) && !compressDirCheck.Checked || mode.Selected == string(ExtractMode) {
		fd := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			*inputFilePaths = []string{uc.URI().Path()}
			inputEntry.SetText(uc.URI().Path())
		}, w)
		if mode.Selected == string(ExtractMode) {
			fd.SetFilter(storageFilterForExtraction())
		}
		fd.Show()
	} else if mode.Selected == string(ArchiveMode) || mode.Selected == string(CompressMode) && compressDirCheck.Checked {
		dialog.ShowFolderOpen(func(uc fyne.ListableURI, err error) {
			if err != nil || uc == nil {
				return
			}
			*inputFilePaths = []string{uc.Path()}
			inputEntry.SetText(uc.Path())
		}, w)
	}
}

func handleOutputFileSelection(w fyne.Window, mode *widget.RadioGroup, inputFilePaths []string, outputEntry *widget.Entry) {
	if mode.Selected == string(DecompressMode) || mode.Selected == string(ExtractMode) {
		dialog.ShowFolderOpen(func(uc fyne.ListableURI, err error) {
			if err != nil || uc == nil {
				return
			}
			outputEntry.SetText(filepath.Join(uc.Path(), removeExtension(filepath.Base(inputFilePaths[0]))))
		}, w)
	} else {
		dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			outputEntry.SetText(uc.URI().Path())
		}, w)
	}
}

func handleStartAction(w fyne.Window, mode *widget.RadioGroup, algo *widget.Select, archiveFormat *widget.Select, checksumAlgo *widget.Select, inputFilePaths []string, inputEntry *widget.Entry, outputEntry *widget.Entry, passwordEntry *widget.Entry, compressDirCheck *widget.Check, numRoutinesEntry *widget.Entry, zstdLevelEntry *widget.Entry, argon2MemoryEntry *widget.Entry, argon2TimeEntry *widget.Entry, argon2ThreadsEntry *widget.Entry, visualCue *widget.Label, progressBar **widget.ProgressBar, outputArea *widget.Entry, logWriter *fyneLogWriter) {
	if mode.Selected == "" || inputEntry.Text == "" || outputEntry.Text == "" {
		dialog.ShowError(errors.New("Please select mode, input, and output"), w)
		return
	}

	visualCue.SetText("Processing...")

	cfg := Config{
		Mode:          OperationMode(mode.Selected),
		Algorithm:     CompressionAlgorithm(algo.Selected),
		ArchiveFormat: ArchiveFormat(archiveFormat.Selected),
		Input:         inputFilePaths,
		Output:        outputEntry.Text,
		Password:      passwordEntry.Text,
		ChecksumAlgo:  ChecksumAlgorithm(checksumAlgo.Selected),
		CompressDir:   compressDirCheck.Checked,
		NumRoutines:   parseInt(numRoutinesEntry.Text, runtime.NumCPU()),
		ZstdLevel:     parseInt(zstdLevelEntry.Text, int(zstd.SpeedDefault)),
		Argon2Memory:  uint32(parseInt(argon2MemoryEntry.Text, 64) * 1024), // Convert KB to KiB
		Argon2Time:    uint32(parseInt(argon2TimeEntry.Text, 1)),
		Argon2Threads: uint8(parseInt(argon2ThreadsEntry.Text, runtime.NumCPU())),
	}

	*progressBar = widget.NewProgressBar()
	(*progressBar).SetValue(0)

	progressDialog := dialog.NewCustom("Processing", "Cancel", container.NewVBox(*progressBar), w)
	progressDialog.Show()

	go func() {
		startTime := time.Now()
		var err error
		switch cfg.Mode {
		case CompressMode:
			err = handleCompressMode(cfg, *progressBar, logWriter, w)
		case DecompressMode:
			err = handleDecompressMode(cfg, *progressBar, logWriter)
		case ArchiveMode:
			err = handleArchiveMode(cfg, *progressBar, logWriter)
		case ExtractMode:
			err = handleExtractMode(cfg, *progressBar, logWriter)
		default:
			log.Printf("Error: Invalid mode '%s'.", cfg.Mode)
			err = fmt.Errorf("invalid mode: %s", cfg.Mode)
		}

		progressDialog.Hide()
		visualCue.SetText("")
		elapsed := time.Since(startTime)

		if err != nil {
			dialog.ShowError(err, w)
		} else {
			showSuccessDialog(w, progressDialog, elapsed)
		}
	}()
}

func handleCompressMode(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter, w fyne.Window) error {
	if len(cfg.Input) != 1 {
		log.Println("Error: Compress mode only supports single file or directory input.")
		return errors.New("invalid input for compress mode")
	}
	info, e := os.Stat(cfg.Input[0])
	if e != nil {
		log.Printf("Error accessing input: %v", e)
		return e
	}
	if info.IsDir() && !cfg.CompressDir {
		log.Println("Error: To compress a directory, use the 'Compress Directory' option.")
		return errors.New("compress directory option not selected")
	} else if !info.IsDir() && cfg.CompressDir {
		log.Println("Error: The 'Compress Directory' option is only for compressing directories.")
		return errors.New("compress directory option is for directories only")
	}

	var err error
	if info.IsDir() && cfg.CompressDir {
		err = compressDirectoryGUI(cfg, progressBar, logWriter)
		if err == nil {
			log.Printf("Successfully compressed directory '%s' to '%s' using %s.", cfg.Input[0], cfg.Output, cfg.Algorithm)
		}
	} else {
		err = compressFileGUI(cfg, progressBar, logWriter)
		if err == nil {
			log.Printf("Successfully compressed '%s' to '%s' using %s.", cfg.Input[0], cfg.Output, cfg.Algorithm)
		}
	}
	return err
}

func handleDecompressMode(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	if len(cfg.Input) != 1 {
		log.Println("Error: Decompress mode only supports single file input.")
		return errors.New("invalid input for decompress mode")
	}
	err := decompressFileGUI(cfg, progressBar, logWriter)
	if err == nil {
		log.Printf("Successfully decompressed '%s' to '%s'.", cfg.Input[0], cfg.Output)
	}
	return err
}

func handleArchiveMode(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	if len(cfg.Input) < 1 {
		log.Println("Error: Archive mode requires at least one input file or directory.")
		return errors.New("at least one input required for archive mode")
	}
	err := createArchiveGUI(cfg, progressBar, logWriter)
	if err == nil {
		log.Printf("Successfully created %s archive '%s' with %d files/directories using %s.", cfg.ArchiveFormat, cfg.Output, len(cfg.Input), cfg.Algorithm)
	}
	return err
}

func handleExtractMode(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	if len(cfg.Input) != 1 {
		log.Println("Error: Extract mode only supports single archive file input.")
		return errors.New("invalid input for extract mode")
	}
	err := extractArchiveGUI(cfg, progressBar, logWriter)
	if err == nil {
		log.Printf("Successfully extracted archive '%s' to '%s'.", cfg.Input[0], cfg.Output)
	}
	return err
}

func updateUIOnModeChange(s string, compressDirCheck *widget.Check, archiveFormat *widget.Select, openFilesButton *widget.Button, openOutputButton *widget.Button) {
	compressDirCheck.Hidden = s != string(CompressMode) && s != string(ArchiveMode)
	archiveFormat.Hidden = s != string(ArchiveMode) && s != string(ExtractMode)
	if s == string(ArchiveMode) || s == string(CompressMode) && compressDirCheck.Checked {
		openFilesButton.SetText("Select Input Folder(s)")
	} else {
		openFilesButton.SetText("Select Input File(s)")
	}
	if s == string(DecompressMode) || s == string(ExtractMode) {
		openOutputButton.SetText("Select Output Folder")
	} else {
		openOutputButton.SetText("Select Output Path")
	}
}

func updateOpenFileButtonText(mode *widget.RadioGroup, compressDirCheck *widget.Check, openFilesButton *widget.Button) {
	if mode.Selected == string(CompressMode) {
		if compressDirCheck.Checked {
			openFilesButton.SetText("Select Input Folder")
		} else {
			openFilesButton.SetText("Select Input File")
		}
	}
}

func createConfigForm(mode *widget.RadioGroup, algo *widget.Select, archiveFormat *widget.Select, checksumAlgo *widget.Select, inputEntry *widget.Entry, openFilesButton *widget.Button, outputEntry *widget.Entry, openOutputButton *widget.Button, passwordEntry *widget.Entry, compressDirCheck *widget.Check, numRoutinesEntry *widget.Entry, zstdLevelEntry *widget.Entry, argon2MemoryEntry *widget.Entry, argon2TimeEntry *widget.Entry, argon2ThreadsEntry *widget.Entry) *fyne.Container {
	return container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Mode", mode),
			widget.NewFormItem("Algorithm", algo),
			widget.NewFormItem("Archive Format", archiveFormat),
			widget.NewFormItem("Checksum Algorithm", checksumAlgo),
			widget.NewFormItem("Input", container.NewBorder(nil, nil, nil, openFilesButton, inputEntry)),
			widget.NewFormItem("Output", container.NewBorder(nil, nil, nil, openOutputButton, outputEntry)),
			widget.NewFormItem("Password", passwordEntry),
			widget.NewFormItem("Compress Directory", compressDirCheck),
			widget.NewFormItem("Number of Routines", numRoutinesEntry),
		),
		widget.NewAccordion(
			widget.NewAccordionItem("Advanced Compression Settings", widget.NewForm(
				widget.NewFormItem("Zstd Level", zstdLevelEntry),
			)),
			widget.NewAccordionItem("Advanced Encryption Settings (Argon2)", widget.NewForm(
				widget.NewFormItem("Memory (KB)", argon2MemoryEntry),
				widget.NewFormItem("Time", argon2TimeEntry),
				widget.NewFormItem("Threads", argon2ThreadsEntry),
			)),
		),
	)
}

func createMainMenu(a fyne.App, w fyne.Window) *fyne.MainMenu {
	return fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("Quit", func() {
				a.Quit()
			}),
		),
		fyne.NewMenu("Help",
			fyne.NewMenuItem("About", func() {
				dialog.ShowInformation("About", "Go Archiver and Compressor v1.2\nSimple GUI for file compression and archiving.", w)
			}),
		),
	)
}

func showSuccessDialog(w fyne.Window, progressDialog dialog.Dialog, elapsed time.Duration) {
	content := container.NewVBox(
		widget.NewLabel("Success!"),
		widget.NewLabel(fmt.Sprintf("Time taken: %s", elapsed)),
		widget.NewButton("OK", func() {
			progressDialog.Hide()
		}),
	)
	successDialog := dialog.NewCustom("Success", "", content, w)
	successDialog.Show()
}

func compressFileGUI(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	inputFile := cfg.Input[0]
	outputFile := cfg.Output
	logWriter.Logf("Compressing file: %s", filepath.Base(inputFile))

	// Calculate checksum before compression
	checksum, err := calculateChecksum(inputFile, cfg.ChecksumAlgo)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	size, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("error getting input file size: %w", err)
	}

	var writer io.WriteCloser
	switch cfg.Algorithm {
	case GzipAlgo:
		gw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
		if err != nil {
			return fmt.Errorf("error creating gzip writer: %w", err)
		}
		writer = gw
	case ZstdAlgo:
		zstdWriter, err := zstd.NewWriter(out, zstd.WithEncoderLevel(zstd.EncoderLevel(cfg.ZstdLevel)))
		if err != nil {
			return fmt.Errorf("error creating zstd writer: %w", err)
		}
		writer = zstdWriter
	case LZ4Algo:
		writer = lz4.NewWriter(out)
	case S2Algo:
		writer = s2.NewWriter(out)
	case NoCompress:
		writer = nopWriteCloser{Writer: out}
	default:
		return fmt.Errorf("unsupported compression algorithm: %s", cfg.Algorithm)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			log.Printf("Error closing writer: %v", err)
		}
	}()

	if cfg.Password != "" {
		encryptedWriter, err := encryptWriter(writer, cfg.Password, cfg)
		if err != nil {
			return fmt.Errorf("encryption setup failed: %w", err)
		}
		writer = encryptedWriter
	}

	buf := make([]byte, bufferSize)
	totalBytes := size.Size()
	bytesWritten := int64(0)

	for {
		n, err := in.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading data: %w", err)
		}
		if n == 0 {
			break
		}

		wn, werr := writer.Write(buf[:n])
		if werr != nil {
			return fmt.Errorf("error writing compressed data: %w", werr)
		}
		bytesWritten += int64(wn)
		if progressBar != nil {
			progressBar.SetValue(float64(bytesWritten) / float64(totalBytes))
		}
	}

	log.Printf("Original checksum (%s): %s (%s)", filepath.Base(inputFile), checksum, cfg.ChecksumAlgo)
	return nil
}

func decompressFileGUI(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	inputFile := cfg.Input[0]
	outputFile := cfg.Output
	logWriter.Logf("Decompressing file: %s", filepath.Base(inputFile))

	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %w", err)
	}
	defer in.Close()

	var reader io.Reader = in

	if cfg.Password != "" {
		reader, err = decryptReader(reader, cfg.Password, cfg)
		if err != nil {
			return fmt.Errorf("decryption setup failed: %w", err)
		}
		if closer, ok := reader.(io.Closer); ok {
			defer closer.Close()
		}
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	var decompressReader io.Reader
	switch cfg.Algorithm {
	case GzipAlgo:
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("error creating gzip reader: %w", err)
		}
		defer gzipReader.Close()
		decompressReader = gzipReader
	case ZstdAlgo:
		zstdReader, err := zstd.NewReader(reader)
		if err != nil {
			return fmt.Errorf("error creating zstd reader: %w", err)
		}
		defer zstdReader.Close()
		decompressReader = zstdReader
	case LZ4Algo:
		lz4Reader := lz4.NewReader(reader)
		decompressReader = lz4Reader
	case S2Algo:
		s2Reader := s2.NewReader(reader)
		decompressReader = s2Reader
	case NoCompress:
		decompressReader = reader
	default:
		return fmt.Errorf("unsupported compression algorithm: %s", cfg.Algorithm)
	}

	fileInfo, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("error getting input file size: %w", err)
	}
	totalBytes := fileInfo.Size()
	bytesRead := int64(0)
	buf := make([]byte, bufferSize)

	for {
		n, err := decompressReader.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading decompressed data: %w", err)
		}
		if n == 0 {
			break
		}

		wn, werr := out.Write(buf[:n])
		if werr != nil {
			return fmt.Errorf("error writing decompressed data: %w", werr)
		}
		bytesRead += int64(wn)
		if progressBar != nil {
			progressBar.SetValue(float64(bytesRead) / float64(totalBytes))
		}
	}

	// Verify checksum after decompression
	checksum, err := calculateChecksum(outputFile, cfg.ChecksumAlgo)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum after decompression: %w", err)
	}
	log.Printf("Checksum after decompression (%s): %s (%s)", filepath.Base(outputFile), checksum, cfg.ChecksumAlgo)

	return nil
}

func createArchiveGUI(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	outputFile := cfg.Output
	logWriter.Logf("Creating %s archive: %s", cfg.ArchiveFormat, filepath.Base(outputFile))

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating archive file: %w", err)
	}
	defer out.Close()

	var compressedWriter io.WriteCloser
	switch cfg.Algorithm {
	case GzipAlgo:
		compressedWriter, err = gzip.NewWriterLevel(out, gzip.BestCompression)
		if err != nil {
			return fmt.Errorf("error creating gzip writer: %w", err)
		}
	case ZstdAlgo:
		compressedWriter, err = zstd.NewWriter(out, zstd.WithEncoderLevel(zstd.EncoderLevel(cfg.ZstdLevel)))
		if err != nil {
			return fmt.Errorf("error creating zstd writer: %w", err)
		}
	case LZ4Algo:
		compressedWriter = lz4.NewWriter(out)
	case S2Algo:
		compressedWriter = s2.NewWriter(out)
	case NoCompress:
		compressedWriter = nopWriteCloser{Writer: out}
	default:
		return fmt.Errorf("unsupported compression algorithm for archiving: %s", cfg.Algorithm)
	}
	defer func() {
		if cErr := compressedWriter.Close(); cErr != nil {
			log.Printf("Error closing compressed writer: %v", cErr)
		}
	}()

	if cfg.Password != "" {
		encryptedWriter, err := encryptWriter(compressedWriter, cfg.Password, cfg)
		if err != nil {
			return fmt.Errorf("encryption setup failed: %w", err)
		}
		compressedWriter = encryptedWriter
	}

	switch cfg.ArchiveFormat {
	case ZipFormat:
		err = createZipArchive(compressedWriter, cfg.Input, progressBar, logWriter)
	case TarGzFormat:
		err = createTarGzArchive(out, cfg.Input, progressBar, logWriter)
	case TarXzFormat:
		err = createTarXzArchive(out, cfg.Input, progressBar, logWriter)
	case SevenZFormat:
		err = errors.New("7z format not yet supported") // Placeholder
	default:
		err = fmt.Errorf("unsupported archive format: %s", cfg.ArchiveFormat)
	}

	return err
}

func extractArchiveGUI(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	inputFile := cfg.Input[0]
	outputPath := cfg.Output
	logWriter.Logf("Extracting archive: %s to %s", filepath.Base(inputFile), outputPath)

	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening archive file: %w", err)
	}
	defer in.Close()

	var reader io.Reader = in

	if cfg.Password != "" {
		reader, err = decryptReader(reader, cfg.Password, cfg)
		if err != nil {
			return fmt.Errorf("decryption setup failed: %w", err)
		}
		if closer, ok := reader.(io.Closer); ok {
			defer closer.Close()
		}
	}

	switch filepath.Ext(inputFile) {
	case ".zip":
		err = extractZipArchive(reader, outputPath, progressBar, logWriter)
	case ".gz":
		err = extractTarGzArchive(reader, outputPath, logWriter)
	case ".xz":
		err = extractTarXzArchive(reader, outputPath, progressBar, logWriter)
	default:
		err = fmt.Errorf("unsupported archive format for extraction: %s", filepath.Ext(inputFile))
	}

	return err
}

func compressDirectoryGUI(cfg Config, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	outputFile := cfg.Output
	inputDir := cfg.Input[0]
	logWriter.Logf("Compressing directory: %s to %s", filepath.Base(inputDir), filepath.Base(outputFile))

	tmpFile, err := os.CreateTemp("", "temp_tar_")
	if err != nil {
		return fmt.Errorf("error creating temporary file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	tarWriter := tar.NewWriter(tmpFile)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			log.Printf("Error closing tar writer: %v", err)
		}
	}()

	var filesToTar []string
	filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			filesToTar = append(filesToTar, path)
		}
		return nil
	})

	filesTared := 0
	totalFiles := len(filesToTar)

	for _, path := range filesToTar {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("error getting file info for '%s': %w", path, err)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("error creating tar header for '%s': %w", path, err)
		}
		header.Name, err = filepath.Rel(inputDir, path)
		if err != nil {
			return fmt.Errorf("error getting relative path for tar header: %w", err)
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("error writing tar header for '%s': %w", path, err)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file '%s': %w", path, err)
		}
		defer file.Close()
		if _, err := io.Copy(tarWriter, file); err != nil {
			return fmt.Errorf("error copying '%s' to tar archive: %w", path, err)
		}
		filesTared++
		if progressBar != nil {
			progressBar.SetValue(float64(filesTared) / float64(totalFiles))
		}
	}
	in, err := os.Open(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("error opening temporary tar file: %w", err)
	}
	defer in.Close()

	var out *os.File
	out, err = os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	var writer io.WriteCloser
	switch cfg.Algorithm {
	case GzipAlgo:
		writer, err = gzip.NewWriterLevel(out, gzip.BestCompression)
		if err != nil {
			return fmt.Errorf("error creating gzip writer: %w", err)
		}
	case ZstdAlgo:
		writer, err = zstd.NewWriter(out, zstd.WithEncoderLevel(zstd.EncoderLevel(cfg.ZstdLevel)))
		if err != nil {
			return fmt.Errorf("error creating zstd writer: %w", err)
		}
	case LZ4Algo:
		writer = lz4.NewWriter(out)
	case S2Algo:
		writer = s2.NewWriter(out)
	default:
		return fmt.Errorf("unsupported compression algorithm: %s", cfg.Algorithm)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			log.Printf("Error closing writer: %v", err)
		}
	}()

	if cfg.Password != "" {
		encryptedWriter, err := encryptWriter(writer, cfg.Password, cfg)
		if err != nil {
			return fmt.Errorf("encryption setup failed: %w", err)
		}
		writer = encryptedWriter
	}

	size, err := in.Stat()
	if err != nil {
		return fmt.Errorf("error getting temporary tar file size: %w", err)
	}

	buf := make([]byte, bufferSize)
	totalBytes := size.Size()
	bytesWritten := int64(0)

	for {
		n, err := in.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading data: %w", err)
		}
		if n == 0 {
			break
		}

		wn, werr := writer.Write(buf[:n])
		if werr != nil {
			return fmt.Errorf("error writing compressed data: %w", werr)
		}
		bytesWritten += int64(wn)
		if progressBar != nil {
			progressBar.SetValue(float64(bytesWritten) / float64(totalBytes))
		}
	}

	return nil
}

// calculateChecksum calculates the checksum of a file using the specified algorithm.
func calculateChecksum(filePath string, algo ChecksumAlgorithm) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file for checksum calculation: %w", err)
	}
	defer file.Close()

	var hashFunc hash.Hash
	switch algo {
	case MD5Checksum:
		hashFunc = md5.New()
	case CRC32Checksum:
		hashFunc = crc32.NewIEEE()
	default:
		return "", fmt.Errorf("unsupported checksum algorithm: %s", algo)
	}

	if _, err := io.Copy(hashFunc, file); err != nil {
		return "", fmt.Errorf("error calculating checksum: %w", err)
	}
	return hex.EncodeToString(hashFunc.Sum(nil)), nil
}

func encryptWriter(w io.Writer, password string, cfg Config) (io.WriteCloser, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("error generating salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, cfg.Argon2Time, cfg.Argon2Memory, cfg.Argon2Threads, 32) // Generate a 256-bit key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	return &gcmChunkWriter{aead: aesGCM, writer: w, nonceSize: nonceSize, salt: salt}, nil
}

type gcmChunkWriter struct {
	aead      cipher.AEAD
	writer    io.Writer
	nonceSize int
	salt      []byte
}

func (g *gcmChunkWriter) Write(p []byte) (n int, err error) {
	if g.salt != nil {
		if _, err := g.writer.Write(g.salt); err != nil {
			return 0, err
		}
		g.salt = nil // Write salt only once
	}
	nonce := make([]byte, g.nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("error generating nonce: %w", err)
	}
	if _, err := g.writer.Write(nonce); err != nil {
		return 0, err
	}

	ciphertext := g.aead.Seal(nil, nonce, p, nil)
	_, err = g.writer.Write(ciphertext)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (g *gcmChunkWriter) Close() error {
	if closer, ok := g.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// decryptReader wraps a reader to decrypt the input in chunks.
func decryptReader(r io.Reader, password string, cfg Config) (io.ReadCloser, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, fmt.Errorf("error reading salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, cfg.Argon2Time, cfg.Argon2Memory, cfg.Argon2Threads, 32) // Generate the same key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	return &gcmChunkReader{aead: aesGCM, reader: r, nonceSize: nonceSize}, nil
}

type gcmChunkReader struct {
	aead      cipher.AEAD
	reader    io.Reader
	nonceSize int
}

func (g *gcmChunkReader) Read(p []byte) (n int, err error) {
	nonce := make([]byte, g.nonceSize)
	if _, err := io.ReadFull(g.reader, nonce); err != nil {
		return 0, err
	}
	ciphertext := make([]byte, len(p)+g.aead.Overhead())
	n, err = io.ReadFull(g.reader, ciphertext)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return 0, err
	}
	if n > 0 {
		plaintext, err := g.aead.Open(nil, nonce, ciphertext[:n], nil)
		if err != nil {
			return 0, err
		}
		return copy(p, plaintext), nil
	}
	return 0, io.EOF

}

func (g *gcmChunkReader) Close() error {
	if closer, ok := g.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type nopWriteCloser struct {
	io.Writer
}

func (n nopWriteCloser) Close() error { return nil }

// fyneLogWriter implements io.Writer to redirect logs to a Fyne multiline entry.
type fyneLogWriter struct {
	output *widget.Entry
	window fyne.Window
	mu     sync.Mutex
}

func newFyneLogWriter(w fyne.Window) *fyneLogWriter {
	return &fyneLogWriter{
		output: widget.NewMultiLineEntry(),
		window: w,
	}
}

func (w *fyneLogWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.output.Append(string(p))
	// Ensure the log output is visible by forcing a refresh
	w.window.Canvas().Refresh(w.output)
	return len(p), nil
}

func (w *fyneLogWriter) Logf(format string, v ...interface{}) {
	w.Write([]byte(fmt.Sprintf(format, v...) + "\n"))
}

func parseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return val
}

func removeExtension(filename string) string {
	ext := filepath.Ext(filename)
	return filename[:len(filename)-len(ext)]
}
func storageFilterForExtraction() storage.FileFilter {
	return storage.NewExtensionFileFilter([]string{".zip", ".tar.gz", ".tgz", ".tar.xz", ".txz"})
}

func createZipArchive(writer io.Writer, inputPaths []string, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	var filesToArchive []string
	for _, inputPath := range inputPaths {
		filepath.WalkDir(inputPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				filesToArchive = append(filesToArchive, path)
			}
			return nil
		})
	}

	totalFiles := len(filesToArchive)
	filesArchived := 0

	for _, filePath := range filesToArchive {
		info, err := os.Stat(filePath)
		if err != nil {
			logWriter.Logf("Error getting info for '%s': %v", filePath, err)
			continue
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			logWriter.Logf("Error creating zip header for '%s': %v", filePath, err)
			continue
		}

		basePath := inputPaths[0] // Assuming the first input path is the base for relative paths
		relativePath, err := filepath.Rel(basePath, filePath)
		if err != nil {
			return fmt.Errorf("error getting relative path: %w", err)
		}
		header.Name = relativePath
		header.Method = zip.Deflate

		w, err := zipWriter.CreateHeader(header)
		if err != nil {
			logWriter.Logf("Error creating header in zip for '%s': %v", filePath, err)
			continue
		}

		file, err := os.Open(filePath)
		if err != nil {
			logWriter.Logf("Error opening file '%s': %v", filePath, err)
			continue
		}
		_, err = io.Copy(w, file)
		file.Close()
		if err != nil {
			logWriter.Logf("Error copying '%s' to zip: %v", filePath, err)
		}

		filesArchived++
		if progressBar != nil {
			progressBar.SetValue(float64(filesArchived) / float64(totalFiles))
		}
	}
	return nil

}

func createTarGzArchive(writer io.Writer, inputPaths []string, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	gzipWriter := gzip.NewWriter(writer)
	defer gzipWriter.Close()

	return createTarArchive(gzipWriter, inputPaths, progressBar, logWriter)

}

func createTarXzArchive(writer io.Writer, inputPaths []string, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	xzWriter, err := xz.NewWriter(writer)
	if err != nil {
		return fmt.Errorf("error creating xz writer: %w", err)
	}
	defer xzWriter.Close()

	return createTarArchive(xzWriter, inputPaths, progressBar, logWriter)

}

func createTarArchive(writer io.Writer, inputPaths []string, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	var filesToArchive []string
	for _, inputPath := range inputPaths {
		filepath.WalkDir(inputPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				filesToArchive = append(filesToArchive, path)
			}
			return nil
		})
	}

	totalFiles := len(filesToArchive)
	filesArchived := 0

	for _, filePath := range filesToArchive {
		info, err := os.Stat(filePath)
		if err != nil {
			logWriter.Logf("Error getting info for '%s': %v", filePath, err)
			continue
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			logWriter.Logf("Error creating tar header for '%s': %v", filePath, err)
			continue
		}

		basePath := inputPaths[0]
		relativePath, err := filepath.Rel(basePath, filePath)
		if err != nil {
			return fmt.Errorf("error getting relative path: %w", err)
		}
		header.Name = relativePath

		if err := tarWriter.WriteHeader(header); err != nil {
			logWriter.Logf("Error writing tar header for '%s': %v", filePath, err)
			continue
		}

		file, err := os.Open(filePath)
		if err != nil {
			logWriter.Logf("Error opening file '%s': %v", filePath, err)
			continue
		}
		_, err = io.Copy(tarWriter, file)
		file.Close()
		if err != nil {
			logWriter.Logf("Error copying '%s' to tar: %v", filePath, err)
		}

		filesArchived++
		if progressBar != nil {
			progressBar.SetValue(float64(filesArchived) / float64(totalFiles))
		}
	}
	return nil

}

func extractZipArchive(reader io.Reader, outputPath string, progressBar *widget.ProgressBar, logWriter *fyneLogWriter) error {
	zipReader, err := zip.NewReader(readerAt{reader}, int64(99999999999)) //TODO: Fix size calculation
	if err != nil {
		return fmt.Errorf("error creating zip reader: %w", err)
	}

	totalFiles := len(zipReader.File)
	filesExtracted := 0

	for _, f := range zipReader.File {
		err := extractFileFromZip(f, outputPath)
		if err != nil {
			logWriter.Logf("Error extracting '%s': %v", f.Name, err)
			return err
		}
		filesExtracted++
		if progressBar != nil {
			progressBar.SetValue(float64(filesExtracted) / float64(totalFiles))
		}
	}
	return nil

}

func extractTarGzArchive(reader io.Reader, outputPath string, logWriter *fyneLogWriter) error {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("error creating gzip reader: %w", err)
	}
	defer gzipReader.Close()

	return extractTarArchive(gzipReader, outputPath, logWriter)

}

func extractTarXzArchive(reader io.Reader, outputPath string, _ *widget.ProgressBar, logWriter *fyneLogWriter) error {
	xzReader, err := xz.NewReader(reader)
	if err != nil {
		return fmt.Errorf("error creating xz reader: %w", err)
	}
	return extractTarArchive(xzReader, outputPath, logWriter)
}

func extractTarArchive(reader io.Reader, outputPath string, logWriter *fyneLogWriter) error {
	tarReader := tar.NewReader(reader)
	fileCount := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar header: %w", err)
		}

		target := filepath.Join(outputPath, header.Name)
		logWriter.Logf("Extracting: %s to %s", header.Name, target)

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return fmt.Errorf("error creating directory '%s': %w", target, err)
				}
			}
		case tar.TypeReg:
			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("error creating output file '%s': %w", target, err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("error writing file '%s': %w", target, err)
			}
			outFile.Close()
		}
		fileCount++
	}
	return nil

}

func extractFileFromZip(file *zip.File, outputPath string) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	path := filepath.Join(outputPath, file.Name)
	if file.FileInfo().IsDir() {
		os.MkdirAll(path, file.Mode())
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err

}

type readerAt struct {
	io.Reader
}

func (r readerAt) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, io.EOF // dummy implementation since zip.NewReader doesn't use ReadAt
}
