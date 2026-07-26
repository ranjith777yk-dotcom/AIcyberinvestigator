"""SQLAlchemy persistence model definitions."""

from cyberinvestigator.infrastructure.database.models.analytics import MLInference, MLModel, MLModelObservation
from cyberinvestigator.infrastructure.database.models.auth import (
    AuditLog,
    Notification,
    Permission,
    Role,
    RolePermission,
    SecurityAlert,
    User,
    UserSession,
)
from cyberinvestigator.infrastructure.database.models.automation import (
    AutomationAction,
    AutomationApproval,
    AutomationExecution,
    AutomationExecutionStep,
    AutomationPlaybook,
)
from cyberinvestigator.infrastructure.database.models.collaboration import (
    CaseReview,
    CaseTeamMember,
    CollaborationTask,
    DiscussionComment,
    DiscussionThread,
)
from cyberinvestigator.infrastructure.database.models.commercial import (
    MarketplaceInstallation,
    MarketplaceListing,
    OrganizationFeatureFlag,
    OrganizationLicense,
)
from cyberinvestigator.infrastructure.database.models.evidence_lab import (
    CustodyEvent,
    EvidenceAnalysisRun,
    ForensicFinding,
)
from cyberinvestigator.infrastructure.database.models.intelligence import (
    IntelligenceIndicator,
    IntelligenceObject,
    IntelligenceRelationship,
)
from cyberinvestigator.infrastructure.database.models.investigation import (
    Artifact,
    Case,
    Evidence,
    InvestigationState,
    Timeline,
    TimelineEvent,
)
from cyberinvestigator.infrastructure.database.models.mobile import MobileDevice, MobileOfflinePolicy
from cyberinvestigator.infrastructure.database.models.operations import (
    AIConversation,
    AIReasoning,
    Plugin,
    PluginExecution,
    Recommendation,
    Report,
    Setting,
    Upload,
)
from cyberinvestigator.infrastructure.database.models.product import (
    ProductFeedback,
    ProductReleasePlan,
    ProductRoadmapItem,
    ProductTelemetryPolicy,
)
from cyberinvestigator.infrastructure.database.models.tenancy import (
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    OrganizationQuota,
    OrganizationSetting,
)
from cyberinvestigator.infrastructure.database.models.threat_hunting import (
    DetectionAlert,
    DetectionRule,
    HuntCorrelation,
    HuntIOCSearch,
    ThreatHunt,
)

__all__ = [
    "AIConversation",
    "AIReasoning",
    "AutomationAction",
    "AutomationApproval",
    "AutomationExecution",
    "AutomationExecutionStep",
    "AutomationPlaybook",
    "MLInference",
    "MLModel",
    "MLModelObservation",
    "MobileDevice",
    "MobileOfflinePolicy",
    "MarketplaceInstallation",
    "MarketplaceListing",
    "OrganizationFeatureFlag",
    "OrganizationLicense",
    "ProductFeedback",
    "ProductReleasePlan",
    "ProductRoadmapItem",
    "ProductTelemetryPolicy",
    "AuditLog",
    "Artifact",
    "Case",
    "CaseReview",
    "CaseTeamMember",
    "CollaborationTask",
    "CustodyEvent",
    "DiscussionComment",
    "DiscussionThread",
    "DetectionAlert",
    "DetectionRule",
    "Evidence",
    "EvidenceAnalysisRun",
    "ForensicFinding",
    "HuntCorrelation",
    "HuntIOCSearch",
    "InvestigationState",
    "IntelligenceIndicator",
    "IntelligenceObject",
    "IntelligenceRelationship",
    "Notification",
    "Organization",
    "OrganizationInvitation",
    "OrganizationMembership",
    "OrganizationQuota",
    "OrganizationSetting",
    "Permission",
    "Plugin",
    "PluginExecution",
    "Recommendation",
    "Report",
    "Role",
    "RolePermission",
    "SecurityAlert",
    "Setting",
    "Timeline",
    "TimelineEvent",
    "ThreatHunt",
    "User",
    "UserSession",
    "Upload",
]
