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

func generateSmallRand() (*big.Int, error) {
	b := make([]byte, 1)

	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
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

	for i := 0; i < n; i++ {
		// 사실 x도 랜덤하게 만들어주면 보안상 더 좋을 것 같음.
		x := big.NewInt(int64(i + 1))
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
	coefficients, err := GenerateCoefficients(k)
	if err != nil {
		panic(err)
	}

	shares, err := ShamirSecretShare(coefficients, k, n)
	if err != nil {
		panic(err)
	}

	// Lagrange Interpolation
	prime := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	prime.Add(prime, big.NewInt(297))
	result := LagrangeInterpolation(shares, prime)
	if result.Cmp(coefficients[0]) == 0 {
		println(result.String())
		println(coefficients[0].String())
		println("Success")
	} else {
		println(result.String())
		println(coefficients[0].String())
		println("Fail")
	}
}
