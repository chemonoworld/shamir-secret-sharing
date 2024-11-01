package main

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type SecretShare struct {
	X *big.Int
	Y *big.Int
}

func generateRand32Bytes() (*big.Int, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}

func generateDistinctRandomInt64s(n int) ([]int64, error) {
	// 1. Generate n random int64s
	randomInt64s := make([]int64, n)
	randMap := make(map[int64]bool)
	for i := 0; i < n; i++ {
		b := make([]byte, 8)

		_, err := rand.Read(b)
		if err != nil {
			return nil, err
		}

		randomInt64s[i] = int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 |
			int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7])<<56
		if _, ok := randMap[randomInt64s[i]]; ok {
			i--
		} else {
			randMap[randomInt64s[i]] = true
		}
	}

	return randomInt64s, nil
}

func GenerateCoefficients(k int) ([]*big.Int, error) {
	coefficients := make([]*big.Int, k)

	for i := 0; i < k; i++ {
		coeff, err := generateRand32Bytes()
		if err != nil {
			return nil, err
		}

		coefficients[i] = coeff
	}

	return coefficients, nil
}

func ShamirSecretShare(coefficients []*big.Int, k, n int) ([]SecretShare, error) {
	if k > n {
		return nil, errors.New("k must be less than n")
	}

	shares := make([]SecretShare, n)
	distinctPointXs, err := generateDistinctRandomInt64s(n)
	if err != nil {
		return nil, err
	}

	for i := 0; i < n; i++ {
		// 사실 x도 랜덤하게 만들어주면 보안상 더 좋을 것 같음.
		x := big.NewInt(distinctPointXs[i])
		y := new(big.Int)

		for j := 0; j < k; j++ {
			// term == a_j * x^j
			term := new(big.Int).Exp(x, big.NewInt(int64(j)), nil)
			term.Mul(term, coefficients[j])
			y.Add(y, term)
		}

		shares[i] = SecretShare{X: x, Y: y}
	}

	return shares, nil
}

func LagrangeInterpolation(shares []SecretShare, prime *big.Int) *big.Int {
	result := new(big.Int)

	for i := 0; i < len(shares); i++ {
		numerator := new(big.Int)
		denominator := new(big.Int)

		numerator.SetInt64(1)
		denominator.SetInt64(1)

		for j := 0; j < len(shares); j++ {
			if i == j {
				continue
			}

			// numerator *= -shares[j].X
			numerator.Mul(numerator, shares[j].X)
			numerator.Neg(numerator)

			// denominator *= shares[i].X - shares[j].X
			denominator.Mul(denominator, new(big.Int).Sub(shares[i].X, shares[j].X))
		}

		// denominator = 1 / denominator
		denominator.ModInverse(denominator, prime)

		// result += shares[i].Y * numerator * denominator
		term := new(big.Int).Mul(new(big.Int).Mul(shares[i].Y, numerator), denominator)
		result.Add(result, term)
	}

	// result = result % prime
	result.Mod(result, prime)

	return result
}

func main() {
	k := 3
	n := 5
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	//prime.Add(prime, big.NewInt(297))
	coefficients, err := GenerateCoefficients(k)
	secretKey := coefficients[0].Mod(coefficients[0], prime)
	if err != nil {
		panic(err)
	}

	shares, err := ShamirSecretShare(coefficients, k, n)
	if err != nil {
		panic(err)
	}

	// Lagrange Interpolation
	result := LagrangeInterpolation(shares, prime)
	if result.Cmp(secretKey) == 0 {
		println(result.String())
		println(secretKey.String())
		println("Success")
	} else {
		println(result.String())
		println(coefficients[0].String())
		println("Fail")
	}
}
