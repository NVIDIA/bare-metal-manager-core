// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	cloudutils "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/ipam"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
)

const (
	siteFabricIPBlockDescription = "Automatically created from Site fabric prefix"
	siteFabricIPBlockNamePrefix  = "site-fabric"
	siteFabricIPBlockReadyMsg    = "IP Block is ready for use"
)

type siteFabricIPBlock struct {
	name            string
	prefix          string
	prefixLength    int
	protocolVersion string
}

// UpdateSiteIPBlocksInDB creates Site-level IP Blocks for fabric prefixes
// reported by the Site controller. Existing root IP Blocks for the same
// provider, Site, prefix, and prefix length are left untouched.
func (mst ManageSite) UpdateSiteIPBlocksInDB(ctx context.Context, siteID uuid.UUID, siteFabricPrefixes []string) error {
	logger := log.With().
		Str("Activity", "UpdateSiteIPBlocksInDB").
		Str("SiteID", siteID.String()).
		Logger()

	logger.Info().Msg("starting activity")

	siteDAO := cdbm.NewSiteDAO(mst.dbSession)
	dbSite, err := siteDAO.GetByID(ctx, nil, siteID, nil, false)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Site from DB by ID")
		return err
	}

	ipBlocks, err := parseSiteFabricIPBlocks(siteFabricPrefixes)
	if err != nil {
		logger.Error().Err(err).Msg("failed to parse Site fabric prefixes")
		return err
	}
	if len(ipBlocks) == 0 {
		logger.Info().Msg("no Site fabric prefixes reported")
		return nil
	}

	ipBlockDAO := cdbm.NewIPBlockDAO(mst.dbSession)
	statusDetailDAO := cdbm.NewStatusDetailDAO(mst.dbSession)
	createdBy := dbSite.CreatedBy

	err = cdb.WithTx(ctx, mst.dbSession, func(tx *cdb.Tx) error {
		if derr := tx.AcquireAdvisoryLock(ctx, siteFabricIPBlocksLockID(dbSite), false); derr != nil {
			logger.Error().Err(derr).Msg("failed to acquire advisory lock for Site fabric IP Blocks")
			return derr
		}

		ipamStorage := ipam.NewIpamStorage(mst.dbSession.DB, tx.GetBunTx())

		for _, ipBlock := range ipBlocks {
			exists, derr := siteFabricIPBlockExists(ctx, tx, ipBlockDAO, dbSite, ipBlock)
			if derr != nil {
				return derr
			}
			if exists {
				logger.Info().
					Str("prefix", ipBlock.prefix).
					Int("prefix_length", ipBlock.prefixLength).
					Msg("Site fabric IP Block already exists")
				continue
			}

			if _, derr = ipam.CreateIpamEntryForIPBlock(
				ctx,
				ipamStorage,
				ipBlock.prefix,
				ipBlock.prefixLength,
				cdbm.IPBlockRoutingTypeDatacenterOnly,
				dbSite.InfrastructureProviderID.String(),
				dbSite.ID.String(),
			); derr != nil {
				logger.Error().
					Err(derr).
					Str("prefix", ipBlock.prefix).
					Int("prefix_length", ipBlock.prefixLength).
					Msg("error creating Site fabric IPAM prefix")
				return derr
			}

			createdIPBlock, derr := ipBlockDAO.Create(ctx, tx, cdbm.IPBlockCreateInput{
				Name:                     ipBlock.name,
				Description:              cloudutils.GetPtr(siteFabricIPBlockDescription),
				SiteID:                   dbSite.ID,
				InfrastructureProviderID: dbSite.InfrastructureProviderID,
				RoutingType:              cdbm.IPBlockRoutingTypeDatacenterOnly,
				Prefix:                   ipBlock.prefix,
				PrefixLength:             ipBlock.prefixLength,
				ProtocolVersion:          ipBlock.protocolVersion,
				Status:                   cdbm.IPBlockStatusReady,
				CreatedBy:                &createdBy,
			})
			if derr != nil {
				logger.Error().Err(derr).Msg("error creating Site fabric IPBlock in DB")
				return derr
			}

			if _, derr = statusDetailDAO.CreateFromParams(
				ctx,
				tx,
				createdIPBlock.ID.String(),
				cdbm.IPBlockStatusReady,
				cloudutils.GetPtr(siteFabricIPBlockReadyMsg),
			); derr != nil {
				logger.Error().Err(derr).Msg("error creating Site fabric IPBlock StatusDetail in DB")
				return derr
			}

			logger.Info().
				Str("IPBlockID", createdIPBlock.ID.String()).
				Str("prefix", ipBlock.prefix).
				Int("prefix_length", ipBlock.prefixLength).
				Msg("created Site fabric IP Block")
		}

		return nil
	})
	if err != nil {
		return err
	}

	logger.Info().Msg("successfully completed activity")

	return nil
}

func parseSiteFabricIPBlocks(siteFabricPrefixes []string) ([]siteFabricIPBlock, error) {
	seen := map[string]bool{}
	ipBlocks := make([]siteFabricIPBlock, 0, len(siteFabricPrefixes))

	for _, cidr := range siteFabricPrefixes {
		parsedPrefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse Site fabric prefix %q: %w", cidr, err)
		}

		parsedPrefix = parsedPrefix.Masked()
		if seen[parsedPrefix.String()] {
			continue
		}
		seen[parsedPrefix.String()] = true

		protocolVersion := cdbm.IPBlockProtocolVersionV6
		if parsedPrefix.Addr().Is4() {
			protocolVersion = cdbm.IPBlockProtocolVersionV4
		}

		ipBlocks = append(ipBlocks, siteFabricIPBlock{
			name:            siteFabricIPBlockName(parsedPrefix),
			prefix:          parsedPrefix.Addr().String(),
			prefixLength:    parsedPrefix.Bits(),
			protocolVersion: protocolVersion,
		})
	}

	return ipBlocks, nil
}

func siteFabricIPBlocksLockID(dbSite *cdbm.Site) uint64 {
	return cdb.GetAdvisoryLockIDFromString(fmt.Sprintf(
		"site-fabric-ip-blocks:%s:%s:%s",
		dbSite.InfrastructureProviderID.String(),
		dbSite.ID.String(),
		cdbm.IPBlockRoutingTypeDatacenterOnly,
	))
}

func siteFabricIPBlockExists(ctx context.Context, tx *cdb.Tx, ipBlockDAO cdbm.IPBlockDAO, dbSite *cdbm.Site, ipBlock siteFabricIPBlock) (bool, error) {
	_, total, err := ipBlockDAO.GetAll(
		ctx,
		tx,
		cdbm.IPBlockFilterInput{
			SiteIDs:                   []uuid.UUID{dbSite.ID},
			InfrastructureProviderIDs: []uuid.UUID{dbSite.InfrastructureProviderID},
			Prefixes:                  []string{ipBlock.prefix},
			PrefixLengths:             []int{ipBlock.prefixLength},
			RoutingTypes:              []string{cdbm.IPBlockRoutingTypeDatacenterOnly},
			ExcludeDerived:            true,
		},
		cdbp.PageInput{Limit: cloudutils.GetPtr(1)},
		nil,
	)
	if err != nil {
		return false, err
	}

	return total > 0, nil
}

func siteFabricIPBlockName(prefix netip.Prefix) string {
	address := prefix.Addr()
	if address.Is4() {
		return fmt.Sprintf("%s-ipv4-%s-%d", siteFabricIPBlockNamePrefix, strings.ReplaceAll(address.String(), ".", "-"), prefix.Bits())
	}

	octets := address.As16()
	return fmt.Sprintf("%s-ipv6-%s-%d", siteFabricIPBlockNamePrefix, hex.EncodeToString(octets[:]), prefix.Bits())
}
