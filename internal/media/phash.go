package media

import (
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"os"
)

func PHashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	img, _, err := image.Decode(file)
	if err != nil {
		return "", err
	}
	return PHashImage(img), nil
}

func PHashImage(img image.Image) string {
	if img == nil {
		return ""
	}
	const size = 32
	const low = 8
	samples := resizeLuma(img, size, size)
	coeffs := make([]float64, low*low)
	for u := 0; u < low; u++ {
		for v := 0; v < low; v++ {
			sum := 0.0
			for x := 0; x < size; x++ {
				for y := 0; y < size; y++ {
					sum += samples[y*size+x] *
						math.Cos((float64(2*x+1)*float64(u)*math.Pi)/(2*size)) *
						math.Cos((float64(2*y+1)*float64(v)*math.Pi)/(2*size))
				}
			}
			cu, cv := 1.0, 1.0
			if u == 0 {
				cu = 1 / math.Sqrt2
			}
			if v == 0 {
				cv = 1 / math.Sqrt2
			}
			coeffs[u*low+v] = 0.25 * cu * cv * sum
		}
	}
	median := medianFloat64(coeffs[1:])
	var bits uint64
	for i, c := range coeffs {
		if i == 0 {
			continue
		}
		if c > median {
			bits |= 1 << uint(63-i)
		}
	}
	out := make([]byte, 8)
	for i := range out {
		out[7-i] = byte(bits >> (8 * i))
	}
	return hex.EncodeToString(out)
}

func SaveImageToTemp(prefix string, data []byte) (string, string, error) {
	if len(data) == 0 {
		return "", "", nil
	}
	file, err := os.CreateTemp("", prefix+"-*")
	if err != nil {
		return "", "", err
	}
	path := file.Name()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", "", err
	}
	hash, err := PHashFile(path)
	if err != nil {
		return path, "", fmt.Errorf("compute phash: %w", err)
	}
	return path, hash, nil
}

func resizeLuma(img image.Image, width, height int) []float64 {
	bounds := img.Bounds()
	out := make([]float64, width*height)
	for y := 0; y < height; y++ {
		srcY := bounds.Min.Y + y*bounds.Dy()/height
		for x := 0; x < width; x++ {
			srcX := bounds.Min.X + x*bounds.Dx()/width
			r, g, b, _ := img.At(srcX, srcY).RGBA()
			out[y*width+x] = 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8)
		}
	}
	return out
}

func medianFloat64(values []float64) float64 {
	cp := append([]float64(nil), values...)
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j] < cp[j-1]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	if len(cp) == 0 {
		return 0
	}
	return cp[len(cp)/2]
}
