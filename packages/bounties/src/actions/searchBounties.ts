import {
  SearchBountiesRequest,
  SearchBountiesRequestSchema,
  SearchBountiesResponse,
  BountyListing,
  TrustRequirements,
  Bounty,
} from "../types/bounty.js";
import { BountyRepository, BountySearchFilters } from "../types/repository.js";

/**
 * Error thrown when bounty search fails
 */
export class SearchBountiesError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "SearchBountiesError";
  }
}

/**
 * Dependencies required for searching bounties
 */
export interface SearchBountiesDeps {
  bountyRepository: BountyRepository;
}

/**
 * Convert a Bounty entity to a BountyListing for search results
 */
function toBountyListing(bounty: Bounty): BountyListing {
  const trustRequirements: TrustRequirements = {
    min_poh_tier: bounty.min_poh_tier ?? 0,
    require_owner_verified_votes: bounty.require_owner_verified_votes ?? false,
  };

  return {
    bounty_id: bounty.bounty_id,
    title: bounty.title,
    description: bounty.description,
    reward: bounty.reward,
    closure_type: bounty.closure_type,
    difficulty_scalar: bounty.difficulty_scalar,
    status: bounty.status,
    tags: bounty.tags,
    is_code_bounty: bounty.is_code_bounty,
    created_at: bounty.created_at,
    trust_requirements: trustRequirements,
  };
}

/**
 * Search bounties
 *
 * This action:
 * 1. Validates the search request
 * 2. Builds search filters from request
 * 3. Queries repository with filters, sorting, and pagination
 * 4. Returns bounty listings with trust requirements
 *
 * @param request - The search bounties request
 * @param deps - Dependencies (repository)
 * @returns The search response with bounty listings and pagination
 */
export async function searchBounties(
  request: SearchBountiesRequest,
  deps: SearchBountiesDeps
): Promise<SearchBountiesResponse> {
  // Validate request
  const parseResult = SearchBountiesRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new SearchBountiesError(
      "Invalid search bounties request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Validate min/max reward range
  if (
    validatedRequest.min_reward !== undefined &&
    validatedRequest.max_reward !== undefined &&
    validatedRequest.min_reward > validatedRequest.max_reward
  ) {
    throw new SearchBountiesError(
      "min_reward cannot be greater than max_reward",
      "INVALID_RANGE"
    );
  }

  // Build search filters
  const filters: BountySearchFilters = {};

  if (validatedRequest.tags && validatedRequest.tags.length > 0) {
    filters.tags = validatedRequest.tags;
  }
  if (validatedRequest.status) {
    filters.status = validatedRequest.status;
  }
  if (validatedRequest.closure_type) {
    filters.closure_type = validatedRequest.closure_type;
  }
  if (validatedRequest.min_reward !== undefined) {
    filters.min_reward = validatedRequest.min_reward;
  }
  if (validatedRequest.max_reward !== undefined) {
    filters.max_reward = validatedRequest.max_reward;
  }
  if (validatedRequest.currency) {
    filters.currency = validatedRequest.currency;
  }
  if (validatedRequest.requester_did) {
    filters.requester_did = validatedRequest.requester_did;
  }
  if (validatedRequest.is_code_bounty !== undefined) {
    filters.is_code_bounty = validatedRequest.is_code_bounty;
  }

  // Execute search
  const searchResult = await deps.bountyRepository.search({
    filters,
    sort_by: validatedRequest.sort_by,
    sort_direction: validatedRequest.sort_direction,
    page: validatedRequest.page,
    page_size: validatedRequest.page_size,
  });

  // Convert bounties to listings with trust requirements
  const bountyListings = searchResult.bounties.map(toBountyListing);

  // Calculate pagination info
  const totalPages = Math.ceil(searchResult.total_count / validatedRequest.page_size);

  return {
    schema_version: "1",
    bounties: bountyListings,
    pagination: {
      page: validatedRequest.page,
      page_size: validatedRequest.page_size,
      total_count: searchResult.total_count,
      total_pages: totalPages,
    },
  };
}
