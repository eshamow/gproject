# Week 3-4 Features: Product Management Layer

## Overview

Week 3-4 implementation adds product management features on top of GitHub Issues, allowing teams to organize work into epics and themes while providing analytics and reporting capabilities.

## Features Implemented

### 1. Epic Management
- **Create, Read, Update, Delete epics**
- **Link GitHub issues to epics** for hierarchical organization
- **Track progress** automatically based on linked issues
- **Visual indicators** with custom colors and status badges
- **Owner assignment** for accountability

**Endpoints:**
- `GET /epics` - View all epics with interactive UI
- `GET /api/epics` - List all epics (JSON)
- `POST /api/epics` - Create new epic
- `GET /api/epics/{id}` - Get epic details with linked issues
- `PUT /api/epics/{id}` - Update epic
- `DELETE /api/epics/{id}` - Delete epic
- `POST /api/epics/{id}/issues` - Link issue to epic
- `DELETE /api/epics/{id}/issues?issue_id={id}` - Unlink issue from epic

### 2. Theme Management & Roadmap
- **Quarterly planning** with themes
- **Group epics into themes** for strategic alignment
- **Status tracking** (planned, in_progress, completed, cancelled)
- **Quarter-based filtering** for roadmap view

**Endpoints:**
- `GET /themes` - View themes and roadmap UI
- `GET /api/themes` - List all themes (JSON)
- `POST /api/themes` - Create new theme
- `GET /api/themes/{id}` - Get theme details with linked epics
- `PUT /api/themes/{id}` - Update theme
- `DELETE /api/themes/{id}` - Delete theme
- `POST /api/themes/{id}/epics` - Link epic to theme
- `DELETE /api/themes/{id}/epics?epic_id={id}` - Unlink epic from theme

### 3. Analytics & Reports
- **Dashboard summary** with key metrics
- **Progress tracking** for epics and overall completion
- **Burndown charts** showing 30-day issue closure trends
- **Velocity tracking** with 12-week rolling average
- **Top performing epics** by completion percentage

**Endpoints:**
- `GET /reports` - Interactive reports dashboard
- `GET /api/reports?type=summary` - Overall statistics
- `GET /api/reports?type=burndown` - 30-day burndown data
- `GET /api/reports?type=velocity` - 12-week velocity data

## Database Schema

```sql
-- Epics table
CREATE TABLE epics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'active',
    color TEXT DEFAULT '#3B82F6',
    owner TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Link issues to epics (many-to-many)
CREATE TABLE issue_epics (
    issue_id INTEGER NOT NULL,
    epic_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (issue_id, epic_id),
    FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
    FOREIGN KEY (epic_id) REFERENCES epics(id) ON DELETE CASCADE
);

-- Themes table for quarterly planning
CREATE TABLE themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    quarter TEXT,
    status TEXT DEFAULT 'planned',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Link epics to themes (many-to-many)
CREATE TABLE epic_themes (
    epic_id INTEGER NOT NULL,
    theme_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (epic_id, theme_id),
    FOREIGN KEY (epic_id) REFERENCES epics(id) ON DELETE CASCADE,
    FOREIGN KEY (theme_id) REFERENCES themes(id) ON DELETE CASCADE
);
```

## UI Features

### Epic Management UI
- **Card-based layout** showing epic overview
- **Progress bars** showing completion percentage
- **Color coding** for visual organization
- **Modal forms** for creating/editing epics
- **Issue search and linking** interface
- **Drag-and-drop** ready structure (future enhancement)

### Theme & Roadmap UI
- **Quarterly grouping** of themes
- **Status badges** for quick status overview
- **Epic assignment** interface
- **Timeline view** ready structure
- **Filtering by quarter** for focused planning

### Reports Dashboard
- **Summary cards** with key metrics
- **Interactive charts** using Chart.js
- **Progress tracking** for active epics
- **Detailed statistics table**
- **Auto-refresh** every 5 minutes
- **Export-ready** data structure

## Security Considerations

All endpoints maintain the existing security model:
- **Authentication required** for all pages and API endpoints
- **CSRF protection** on state-changing operations
- **SQL injection prevention** with parameterized queries
- **Input validation** on all user inputs
- **Secure session management** maintained

## Testing

Comprehensive test coverage added:
```bash
# Run epic and theme tests
go test ./cmd/web -run "TestEpics|TestThemes|TestReports" -v
```

Tests cover:
- Epic CRUD operations
- Theme CRUD operations
- Issue-to-epic linking
- Epic-to-theme linking
- Report generation
- Data integrity

## Usage Examples

### Creating an Epic
```javascript
fetch('/api/epics', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        title: 'Performance Improvements',
        description: 'Optimize database queries and caching',
        color: '#10B981',
        owner: 'backend-team',
        status: 'active'
    })
});
```

### Linking Issues to Epic
```javascript
fetch('/api/epics/1/issues', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        issue_id: 42
    })
});
```

### Creating a Theme
```javascript
fetch('/api/themes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        name: 'Q1 2025 Goals',
        description: 'First quarter objectives',
        quarter: '2025-Q1',
        status: 'planned'
    })
});
```

## Performance Optimizations

- **Indexed foreign keys** for fast joins
- **Aggregated queries** to minimize database calls
- **Efficient SQL** with proper JOIN strategies
- **Client-side caching** for static data
- **Lazy loading** for detailed views

## Future Enhancements

While the MVP is complete, future iterations could add:
1. **Gantt charts** for timeline visualization
2. **Dependencies** between epics
3. **Capacity planning** based on velocity
4. **Custom fields** for epics and themes
5. **Bulk operations** for issue assignment
6. **Export to CSV/JSON** for reports
7. **Webhook notifications** for epic updates
8. **Team velocity tracking** per owner
9. **Milestone integration** with GitHub
10. **Burnup charts** alongside burndown

## Migration from Week 2

The Week 3-4 features build seamlessly on top of Week 2:
- Database migrations run automatically on startup
- No breaking changes to existing functionality
- All Week 2 features (sync, webhooks, SSE) continue working
- New tables don't affect existing data

## Deployment Notes

No additional deployment requirements:
- Same environment variables as Week 2
- Database migrations automatic
- No new dependencies
- No configuration changes needed

Simply deploy the updated binary and the new features will be available immediately.