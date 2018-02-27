// Copyright 2016 The go-amero Authors
// This file is part of the go-amero library.
//
// The go-amero library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-amero library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-amero library. If not, see <http://www.gnu.org/licenses/>.

package ethclient

import "github.com/amero/go-amero"

// Verify that Client implements the amero interfaces.
var (
	_ = amero.ChainReader(&Client{})
	_ = amero.TransactionReader(&Client{})
	_ = amero.ChainStateReader(&Client{})
	_ = amero.ChainSyncReader(&Client{})
	_ = amero.ContractCaller(&Client{})
	_ = amero.GasEstimator(&Client{})
	_ = amero.GasPricer(&Client{})
	_ = amero.LogFilterer(&Client{})
	_ = amero.PendingStateReader(&Client{})
	// _ = amero.PendingStateEventer(&Client{})
	_ = amero.PendingContractCaller(&Client{})
)
