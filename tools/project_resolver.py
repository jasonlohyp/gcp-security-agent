from google.cloud import resourcemanager_v3

def resolve_projects(project_id: str = None, folder_id: str = None, org_id: str = None) -> list[str]:
    """
    Resolves a list of active GCP project IDs based on the provided scope.
    
    Args:
        project_id: A single project ID.
        folder_id: A folder ID (discover all projects under it).
        org_id: An organization ID (discover all projects under it).
        
    Returns:
        A list of active project IDs.
    """
    if project_id:
        return [project_id]
    
    client = resourcemanager_v3.ProjectsClient()
    
    # query uses 'parent' field which handles both folders and organizations
    # format: 'folders/123' or 'organizations/456'
    if folder_id:
        parent = f"folders/{folder_id}"
    elif org_id:
        parent = f"organizations/{org_id}"
    else:
        # If nothing is provided, return an empty list or raise an error? 
        # main.py handles validation, so we return empty.
        return []

    # search_projects handles recursive discovery across children
    # query for active projects only
    query = f"parent:{parent} state:ACTIVE"
    request = resourcemanager_v3.SearchProjectsRequest(query=query)
    
    project_ids = []
    projects = client.search_projects(request=request)
    
    for project in projects:
        project_ids.append(project.project_id)
        
    return project_ids
