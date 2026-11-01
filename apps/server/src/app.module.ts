import { type DynamicModule, Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, DiscoveryModule } from '@nestjs/core';
import { ServeStaticModule } from '@nestjs/serve-static';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { LoggerModule } from 'nestjs-pino';
import { type IncomingMessage } from 'node:http';
import { AiModule } from './ai/ai.module';
import { AuditController } from './audit/audit.controller';
import { AuthModule } from './auth/auth.module';
import { AuthGuard, CsrfGuard, PermissionsGuard } from './auth/guards';
import { DuplicateKeyFilter } from './common/duplicate-key.filter';
import { IntegrationErrorFilter } from './common/integration-error.filter';
import { type AppConfig } from './config/app-config';
import { CoreModule } from './core/core.module';
import { FindingsModule } from './findings/findings.module';
import { HealthController } from './health/health.controller';
import { MetricsController } from './health/metrics.controller';
import { OpenApiController, OpenApiService } from './health/openapi';
import { IntelModule } from './intel/intel.module';
import { ReportsModule } from './reports/reports.module';
import { CredentialsModule } from './credentials/credentials.module';
import { SavedViewsModule } from './saved-views/saved-views.module';
import { JobsModule } from './jobs/jobs.module';
import { PrScansModule } from './pr-scans/pr-scans.module';
import { ScansModule } from './scans/scans.module';
import { SettingsController } from './settings/settings.controller';
import { SettingsTransferService } from './settings/settings-transfer.service';
import { SourcesModule } from './sources/sources.module';
import { TicketsModule } from './tickets/tickets.module';
import { TeamsController } from './teams/teams.controller';
import { UsersModule } from './users/users.module';
import { WorkerModule } from './worker/worker.module';

const QUIET_PATHS = new Set(['/healthz', '/readyz']);

export function loggerModule(config: AppConfig): DynamicModule {
  return LoggerModule.forRoot({
    pinoHttp: {
      level: config.logLevel,
      // Never log credentials or session material.
      redact: {
        paths: ['req.headers.cookie', 'req.headers.authorization', 'req.headers["x-csrf-token"]', 'res.headers["set-cookie"]'],
        censor: '[redacted]',
      },
      autoLogging: { ignore: (req: IncomingMessage) => QUIET_PATHS.has(req.url ?? '') },
      base: { role: config.role, version: config.version },
    },
  });
}

@Module({})
export class AppModule {
  static register(config: AppConfig): DynamicModule {
    return {
      module: AppModule,
      imports: [
        CoreModule.forRoot(config),
        loggerModule(config),
        ThrottlerModule.forRoot([{ name: 'default', ttl: 60_000, limit: 300 }]),
        DiscoveryModule,
        AuthModule,
        UsersModule,
        JobsModule,
        SourcesModule,
        ScansModule,
        PrScansModule,
        FindingsModule,
        TicketsModule,
        AiModule,
        IntelModule,
        ReportsModule,
        CredentialsModule,
        SavedViewsModule,
        ...(config.webDir
          ? [
              ServeStaticModule.forRoot({
                rootPath: config.webDir,
                exclude: ['/api/{*path}', '/healthz', '/readyz'],
                serveStaticOptions: {
                  setHeaders: (res, path) => {
                    // Vite emits content-hashed assets; index.html must always be revalidated.
                    res.setHeader('Cache-Control', /[\\/]assets[\\/]/.test(path) ? 'public, max-age=31536000, immutable' : 'no-cache');
                  },
                },
              }),
            ]
          : []),
        ...(config.role === 'all' ? [WorkerModule] : []),
      ],
      controllers: [HealthController, MetricsController, OpenApiController, TeamsController, AuditController, SettingsController],
      providers: [
        OpenApiService,
        SettingsTransferService,
        // Guard order matters: rate limit, then CSRF, then authenticate, then authorise.
        { provide: APP_GUARD, useClass: ThrottlerGuard },
        { provide: APP_GUARD, useExisting: CsrfGuard },
        { provide: APP_GUARD, useExisting: AuthGuard },
        { provide: APP_GUARD, useExisting: PermissionsGuard },
        { provide: APP_FILTER, useClass: DuplicateKeyFilter },
        { provide: APP_FILTER, useClass: IntegrationErrorFilter },
      ],
    };
  }
}

@Module({})
export class WorkerAppModule {
  static register(config: AppConfig): DynamicModule {
    return { module: WorkerAppModule, imports: [CoreModule.forRoot(config), loggerModule(config), JobsModule, SourcesModule, ScansModule, PrScansModule, TicketsModule, IntelModule, CredentialsModule, WorkerModule] };
  }
}
