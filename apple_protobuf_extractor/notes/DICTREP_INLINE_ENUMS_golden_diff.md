# Golden diff caused by the dictRep data-flow enum recovery (GeoServices, 2026-10-13)

Committed `tests/golden/GeoServices.json` vs the final working tree: **89 keys** (locationd and CoreLocationProtobuf: 0).
The committed golden equals HEAD + the other session's `_valid_value_bitmask` hunks exactly (0 differences), so every key below is caused by this change.
To accept: `MACHO_UPDATE_GOLDEN=1 ./venv/bin/python3 -m pytest apple_protobuf_extractor/tests/test_golden_output.py` and review the git diff of tests/golden/GeoServices.json (only after the other session's struct work is settled, since the golden is regenerated from the whole tree).

## Fields int32 -> enum (42)

- `GEOComponentAction.actions`  int32 -> `ComponentActionActions`
- `GEOHours.days`  int32 -> `HoursDays`
- `GEOPDActionDataFilter.linkTypes`  int32 -> `LinkType`
- `GEOPDAutocompletePlaceContextMetadata.clientizationFeatures`  int32 -> `ClientizationFeature`
- `GEOPDBatchReverseGeocodingParameters.additionalPlaceTypes`  int32 -> `PDBatchReverseGeocodingParametersAdditionalPlaceTypes`
- `GEOPDCategorySearchParameters.knownRefinementTypes`  int32 -> `ResultRefinement`
- `GEOPDCategorySearchParameters.supportedPlaceSummaryFormatTypes`  int32 -> `PlaceSummaryFormatType`
- `GEOPDCategorySearchParameters.supportedRelatedEntitySectionTypes`  int32 -> `RelatedEntitySectionType`
- `GEOPDCategorySearchParameters.supportedSearchSectionTypes`  int32 -> `SearchSectionType`
- `GEOPDCategorySearchParameters.supportedSearchTierTypes`  int32 -> `SearchTierMetadata`
- `GEOPDETAFilter.transportTypes`  int32 -> `PDETAFilterTransportTypes`
- `GEOPDExtendedGeoLookupResult.status`  int32 -> `ExtendedGeoLookupResultsStatus`
- `GEOPDExtensionParams.extensionTypes`  int32 -> `ExtensionType`
- `GEOPDExternalActionFilter.componentTypes`  int32 -> `ComponentType`
- `GEOPDGroundDataBuild.capabilitys`  int32 -> `PDGroundDataBuildCapabilitys`
- `GEOPDGuidesHomeParameters.supportedFixedSectionTypes`  int32 -> `GuidesHomeFixedSectionType`
- `GEOPDGuidesHomeParameters.supportedRepeatableSectionTypes`  int32 -> `GuidesHomeRepeatableSectionType`
- `GEOPDMapsSearchHomeParameters.supportedSectionTypes`  int32 -> `PDMapsSearchHomeParametersSupportedSectionTypes`
- `GEOPDResultSnippetFilter.supportedChildActions`  int32 -> `ChildActionType`
- `GEOPDSearchBrowseCategorySuggestionParameters.engineTypes`  int32 -> `CarEngineType`
- `GEOPDSearchParameters.knownRefinementTypes`  int32 -> `ResultRefinement`
- `GEOPDSearchParameters.supportedPlaceSummaryFormatTypes`  int32 -> `PlaceSummaryFormatType`
- `GEOPDSearchParameters.supportedRelatedEntitySectionTypes`  int32 -> `RelatedEntitySectionType`
- `GEOPDSearchParameters.supportedSearchSectionTypes`  int32 -> `SearchSectionType`
- `GEOPDSearchParameters.supportedSearchTierTypes`  int32 -> `SearchTierMetadata`
- `GEOPDSearchQueryCompletionMetadata.completionSourceTypes`  int32 -> `CompletionSourceType`
- `GEOPDSearchQueryFuzzyMatchV2Metadata.rewriteTypes`  int32 -> `PDSearchQueryFuzzyMatchV2MetadataRewriteTypes`
- `GEOPDSearchQueryGeoNormalizerMetadata.normalizers`  int32 -> `PDSearchQueryGeoNormalizerMetadataNormalizers`
- `GEOPDSearchQueryGeoTagMetadata.geoRewriteTypes`  int32 -> `PDSearchQueryGeoTagMetadataGeoRewriteTypes`
- `GEOPDSearchQueryGeoTagMetadata.tagSources`  int32 -> `PDSearchQueryGeoTagMetadataTagSources`
- `GEOPDSearchQueryIntentMetadata.intentSources`  int32 -> `PDSearchQueryIntentMetadataIntentSources`
- `GEOPDSearchQueryIntentMetadata.rewrittenQueryTypes`  int32 -> `PDSearchQueryIntentMetadataRewrittenQueryTypes`
- `GEOPDSearchRewrittenQueryNonPayloadField.pipelineType`  int32 -> `PDSearchRewrittenQueryNonPayloadFieldPipelineType`
- `GEOPDSearchTriggerFeature.completionSourceTypes`  int32 -> `CompletionSourceType`
- `GEOPDSpatialEventLookupParameters.categoryFilters`  int32 -> `SpatialEventLookupCategory`
- `GEOPDSpatialLookupResult.mappedCategorys`  int32 -> `SpatialLookupCategory`
- `GEOPDSpatialPlaceLookupParameters.categoryFilters`  int32 -> `SpatialPlaceLookupCategory`
- `GEOPDVendorIDLink.reservationTypes`  int32 -> `RestaurantReservationType`
- `GEOPDWebModuleConfiguration.type`  int32 -> `PDWebModuleConfigurationType`
- `GEOSearchAttributionSource.attributionRequirements`  int32 -> `SearchAttributionSourceAttributionRequirements`
- `GEOSearchAttributionSource.suppressAttributionLogos`  int32 -> `ActionComponent`
- `GEOTerritoryDataTerritoryInfo.territoryTypes`  int32 -> `TerritoryDataTerritoryInfoTerritoryTypes`

## Existing enums whose values changed (5)

- `GEOPDCandidateFilterReason.<enum:CandidateFilterReasonType>`: 5 -> 5 values; numbers [0, 1, 2, 3] -> [15300, 15301, 15302, 15303]
- `GEOPDOverallFilterReason.<enum:OverallFilterReasonType>`: 8 -> 8 values; numbers [0, 1, 2, 3] -> [15400, 15401, 15402, 15403]
- `GEOPDPlaceRefinementParameters.<enum:PDPlaceRefinementParametersPlaceTypeHint>`: 17 -> 22 values; numbers [0, 8, 9, 10] -> [0, 1, 2, 4]
- `GEOPDReverseGeocodingParameters.<enum:PDReverseGeocodingParametersPlaceTypeLimit>`: 17 -> 22 values; numbers [0, 8, 9, 10] -> [0, 1, 2, 4]
- `GEOPDVendorSpecificPlaceRefinementParameters.<enum:PDVendorSpecificPlaceRefinementParametersPlaceTypeHint>`: 17 -> 22 values; numbers [0, 8, 9, 10] -> [0, 1, 2, 4]

## New enum entries (42)

- `GEOComponentAction.<enum:ComponentActionActions>`: 5 values, first (0, 'COMPONENT_ACTION_ACTIONS_ACTION_UNKNOWN')
- `GEOHours.<enum:HoursDays>`: 8 values, first (0, 'HOURS_DAYS_SUNDAY')
- `GEOPDActionDataFilter.<enum:LinkType>`: 4 values, first (0, 'LINK_TYPE_UNKNOWN')
- `GEOPDAutocompletePlaceContextMetadata.<enum:ClientizationFeature>`: 5 values, first (0, 'CLIENTIZATION_FEATURE_UNKNOWN')
- `GEOPDBatchReverseGeocodingParameters.<enum:PDBatchReverseGeocodingParametersAdditionalPlaceTypes>`: 22 values, first (0, 'PD_BATCH_REVERSE_GEOCODING_PARAMETERS_ADDITIONAL_PLACE_TYPES_UNKNOWN_PLACE_TYPE')
- `GEOPDCategorySearchParameters.<enum:PlaceSummaryFormatType>`: 5 values, first (0, 'PLACE_SUMMARY_FORMAT_TYPE_UNKNOWN')
- `GEOPDCategorySearchParameters.<enum:RelatedEntitySectionType>`: 2 values, first (0, 'RELATED_ENTITY_SECTION_TYPE_UNKNOWN')
- `GEOPDCategorySearchParameters.<enum:ResultRefinement>`: 6 values, first (0, 'RESULT_REFINEMENT_TYPE_UNKNOWN')
- `GEOPDCategorySearchParameters.<enum:SearchSectionType>`: 3 values, first (0, 'SEARCH_SECTION_TYPE_UNKNOWN')
- `GEOPDCategorySearchParameters.<enum:SearchTierMetadata>`: 3 values, first (0, 'SEARCH_TIER_METADATA_UNKNOWN')
- `GEOPDETAFilter.<enum:PDETAFilterTransportTypes>`: 7 values, first (0, 'PDETA_FILTER_TRANSPORT_TYPES_AUTOMOBILE')
- `GEOPDExtendedGeoLookupResult.<enum:ExtendedGeoLookupResultsStatus>`: 3 values, first (0, 'EXTENDED_GEO_LOOKUP_RESULTS_STATUS_UNDEFINED')
- `GEOPDExtensionParams.<enum:ExtensionType>`: 3 values, first (0, 'EXTENSION_TYPE_UNKNOWN')
- `GEOPDExternalActionFilter.<enum:ComponentType>`: 89 values, first (0, 'COMPONENT_TYPE_UNKNOWN')
- `GEOPDGroundDataBuild.<enum:PDGroundDataBuildCapabilitys>`: 2 values, first (1, 'PD_GROUND_DATA_BUILD_CAPABILITYS_PANORAMIC')
- `GEOPDGuidesHomeParameters.<enum:GuidesHomeFixedSectionType>`: 4 values, first (0, 'GUIDES_HOME_FIXED_SECTION_TYPE_UNKNOWN')
- `GEOPDGuidesHomeParameters.<enum:GuidesHomeRepeatableSectionType>`: 5 values, first (0, 'GUIDES_HOME_REPEATABLE_SECTION_TYPE_UNKNOWN')
- `GEOPDMapsSearchHomeParameters.<enum:PDMapsSearchHomeParametersSupportedSectionTypes>`: 6 values, first (0, 'PD_MAPS_SEARCH_HOME_PARAMETERS_SUPPORTED_SECTION_TYPES_UNKNOWN')
- `GEOPDResultSnippetFilter.<enum:ChildActionType>`: 8 values, first (0, 'CHILD_ACTION_TYPE_UNKNOWN')
- `GEOPDSearchBrowseCategorySuggestionParameters.<enum:CarEngineType>`: 5 values, first (0, 'CAR_ENGINE_TYPE_UNKNOWN')
- `GEOPDSearchParameters.<enum:PlaceSummaryFormatType>`: 5 values, first (0, 'PLACE_SUMMARY_FORMAT_TYPE_UNKNOWN')
- `GEOPDSearchParameters.<enum:RelatedEntitySectionType>`: 2 values, first (0, 'RELATED_ENTITY_SECTION_TYPE_UNKNOWN')
- `GEOPDSearchParameters.<enum:ResultRefinement>`: 6 values, first (0, 'RESULT_REFINEMENT_TYPE_UNKNOWN')
- `GEOPDSearchParameters.<enum:SearchSectionType>`: 3 values, first (0, 'SEARCH_SECTION_TYPE_UNKNOWN')
- `GEOPDSearchParameters.<enum:SearchTierMetadata>`: 3 values, first (0, 'SEARCH_TIER_METADATA_UNKNOWN')
- `GEOPDSearchQueryCompletionMetadata.<enum:CompletionSourceType>`: 14 values, first (0, 'COMPLETION_SOURCE_TYPE_DEFAULT')
- `GEOPDSearchQueryFuzzyMatchV2Metadata.<enum:PDSearchQueryFuzzyMatchV2MetadataRewriteTypes>`: 3 values, first (0, 'PD_SEARCH_QUERY_FUZZY_MATCH_V2_METADATA_REWRITE_TYPES_LAZY_REWRITE_NONE')
- `GEOPDSearchQueryGeoNormalizerMetadata.<enum:PDSearchQueryGeoNormalizerMetadataNormalizers>`: 5 values, first (1, 'PD_SEARCH_QUERY_GEO_NORMALIZER_METADATA_NORMALIZERS_NORMALIZE')
- `GEOPDSearchQueryGeoTagMetadata.<enum:PDSearchQueryGeoTagMetadataGeoRewriteTypes>`: 6 values, first (1, 'PD_SEARCH_QUERY_GEO_TAG_METADATA_GEO_REWRITE_TYPES_PREFIX_TO_FIRST_DIGIT')
- `GEOPDSearchQueryGeoTagMetadata.<enum:PDSearchQueryGeoTagMetadataTagSources>`: 27 values, first (1, 'PD_SEARCH_QUERY_GEO_TAG_METADATA_TAG_SOURCES_CRF')
- `GEOPDSearchQueryIntentMetadata.<enum:PDSearchQueryIntentMetadataIntentSources>`: 7 values, first (0, 'PD_SEARCH_QUERY_INTENT_METADATA_INTENT_SOURCES_NONE')
- `GEOPDSearchQueryIntentMetadata.<enum:PDSearchQueryIntentMetadataRewrittenQueryTypes>`: 22 values, first (0, 'PD_SEARCH_QUERY_INTENT_METADATA_REWRITTEN_QUERY_TYPES_NONE_REWRITTEN_QUERY_TYPE')
- `GEOPDSearchRewrittenQueryNonPayloadField.<enum:PDSearchRewrittenQueryNonPayloadFieldPipelineType>`: 4 values, first (0, 'PD_SEARCH_REWRITTEN_QUERY_NON_PAYLOAD_FIELD_PIPELINE_TYPE_NONE')
- `GEOPDSearchTriggerFeature.<enum:CompletionSourceType>`: 14 values, first (0, 'COMPLETION_SOURCE_TYPE_DEFAULT')
- `GEOPDSpatialEventLookupParameters.<enum:SpatialEventLookupCategory>`: 14 values, first (0, 'SPATIAL_EVENT_LOOKUP_CATEGORY_UNKNOWN')
- `GEOPDSpatialLookupResult.<enum:SpatialLookupCategory>`: 23 values, first (0, 'SPATIAL_LOOKUP_CATEGORY_UNKNOWN')
- `GEOPDSpatialPlaceLookupParameters.<enum:SpatialPlaceLookupCategory>`: 24 values, first (0, 'SPATIAL_PLACE_LOOKUP_CATEGORY_UNKNOWN')
- `GEOPDVendorIDLink.<enum:RestaurantReservationType>`: 3 values, first (0, 'RESTAURANT_RESERVATION_TYPE_UNKNOWN')
- `GEOPDWebModuleConfiguration.<enum:PDWebModuleConfigurationType>`: 1 values, first (0, 'PD_WEB_MODULE_CONFIGURATION_TYPE_WEB_MODULE_TYPE_GENERIC')
- `GEOSearchAttributionSource.<enum:ActionComponent>`: 4 values, first (0, 'ACTION_COMPONENT_ALL')
- `GEOSearchAttributionSource.<enum:SearchAttributionSourceAttributionRequirements>`: 6 values, first (1, 'SEARCH_ATTRIBUTION_SOURCE_ATTRIBUTION_REQUIREMENTS_INFO')
- `GEOTerritoryDataTerritoryInfo.<enum:TerritoryDataTerritoryInfoTerritoryTypes>`: 4 values, first (0, 'TERRITORY_DATA_TERRITORY_INFO_TERRITORY_TYPES_UNKNOWN')
